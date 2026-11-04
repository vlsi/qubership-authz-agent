// Copyright 2024-2026 Netcracker Technology Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"net/http"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/proxy"
	"github.com/gofiber/fiber/v2/utils"
	"github.com/netcracker/qubership-core-lib-go/v3/context-propagation/baseproviders/xrequestid"
	"github.com/netcracker/qubership-core-lib-go/v3/context-propagation/ctxmanager"

	"authz-agent/components/authz-agent/internal/legacy"
)

// originalPathHeader records, for the decision log, the route a legacy
// request used; every legacy request is logged as the decision at
// authorize.
const originalPathHeader = "X-Authz-Original-Path"

// The decision-log download can carry a whole run's decisions, so it is
// given a timeout of its own rather than the client's default.
const (
	decisionLogsTimeout = 30 * time.Second
)

// RegisterPublic adds the public routes to app: the check routes of the
// legacy access-control API translated by package legacy, /api-version,
// /health, the decision-log download, and 404 {"message":"not found"} for
// every other path. Each answers as the Envoy container answered it. The
// download is relayed to the collector of Options.CollectorURL when the
// decisions are not stored in the service. A route accepts any method, as
// the Envoy path matches did; the check routes then read the body, and the
// filter routes the query, whatever the method.
func (s *Server) RegisterPublic(app *fiber.App) {
	app.Use(s.requestID)
	switch {
	case s.logs != nil && s.logs.Store() != nil:
		app.All("/internal/v1/decision-logs", s.download)
	case s.opts.CollectorURL != "":
		app.All("/internal/v1/decision-logs", s.relay(s.opts.CollectorURL, "collector", decisionLogsTimeout))
	}
	app.All("/access/v1/check/resource/bulk/operations", s.checkResourceBulkOperations(false))
	app.All("/preview/v1/check/resource/bulk/operations", s.checkResourceBulkOperations(false))
	app.All("/access/v1/check/resource/bulk", s.checkResourceBulk)
	app.All("/access/v1/check/resource", s.checkResource("/access/v1/check/resource", false))
	app.All("/access/v1/check/filter", s.checkFilter("/access/v1/check/filter"))
	app.All("/access/v2/check/resource/bulk/operations", s.checkResourceBulkOperations(true))
	app.All("/preview/v2/check/resource/bulk/operations", s.checkResourceBulkOperations(true))
	app.All("/access/v2/check/resource", s.checkResource("/access/v2/check/resource", true))
	app.All("/access/v2/check/filter", s.checkFilter("/access/v2/check/filter"))
	app.All("/api-version", apiVersion)
	app.All("/health", s.publicHealth)
	app.Use(s.notFound)
}

// requestID gives a request without an X-Request-Id one, as Envoy did, so
// input.requestId and the decision log always carry an id. The propagated
// context built an id of its own from the same missing header, so the
// generated id replaces it and the response header it was propagated into:
// a decision logged under one id and a log line written under another
// cannot be brought together afterwards.
func (s *Server) requestID(c *fiber.Ctx) error {
	if c.Get(fiber.HeaderXRequestID) != "" {
		return c.Next()
	}
	id := utils.UUIDv4()
	c.Request().Header.Set(fiber.HeaderXRequestID, id)
	c.Response().Header.Set(fiber.HeaderXRequestID, id)
	// A process whose context providers were never registered has no
	// propagated id for the generated one to disagree with, and the header
	// carries it there on its own; the platform's Fiber builder registers
	// them before any route runs.
	ctx, err := ctxmanager.SetContextObject(c.UserContext(), xrequestid.X_REQUEST_ID_COTEXT_NAME,
		xrequestid.NewXRequestIdContextObject(id))
	if err == nil {
		c.SetUserContext(ctx)
	}
	return c.Next()
}

func (s *Server) notFound(c *fiber.Ctx) error {
	s.opts.Log.DebugC(c.UserContext(), "no route for %s %s", c.Method(), c.Path())
	return c.Status(http.StatusNotFound).JSON(fiber.Map{"message": "not found"})
}

// publicHealth is the public surface's /health: the service's own health
// for GET, and 405 for any other method, as access-control answers.
func (s *Server) publicHealth(c *fiber.Ctx) error {
	if c.Method() != fiber.MethodGet {
		return c.Status(http.StatusMethodNotAllowed).JSON(fiber.Map{"message": "method not allowed"})
	}
	return s.health(c)
}

// download serves the stored decisions as NDJSON, as the collector did,
// for GET; any other method is 405.
func (s *Server) download(c *fiber.Ctx) error {
	if c.Method() != fiber.MethodGet {
		return c.Status(http.StatusMethodNotAllowed).JSON(fiber.Map{"message": "method not allowed"})
	}
	// Streamed, not read into memory: the log is capped by the volume's
	// sizeLimit, 2Gi in the production profile, and a copy of that on the
	// decision path would take the check API down with it. Streaming also
	// keeps the append lock off the transfer, so the queue drains while a
	// download runs.
	f, size, err := s.logs.Store().Open()
	if err != nil {
		s.opts.Log.ErrorC(c.UserContext(), "decision log download failed: %v", err)
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"message": "failed to read decision logs"})
	}
	c.Set(fiber.HeaderContentType, "application/x-ndjson")
	if f == nil {
		return c.Send(nil)
	}
	// fasthttp closes a body stream that is an io.Closer once it is written.
	return c.SendStream(f, int(size))
}

// relay forwards the request, path and query included, to the container
// at base, and its answer back. When the container does not answer within
// timeout, the caller gets 503 naming the container.
func (s *Server) relay(base, name string, timeout time.Duration) fiber.Handler {
	base = strings.TrimRight(base, "/")
	return func(c *fiber.Ctx) error {
		if err := proxy.DoTimeout(c, base+c.OriginalURL(), timeout); err != nil {
			s.opts.Log.WarnC(c.UserContext(), "%s did not answer within %s: %v", name, timeout, err)
			return c.Status(http.StatusServiceUnavailable).JSON(fiber.Map{"message": name + " unavailable: " + err.Error()})
		}
		return nil
	}
}

func (s *Server) checkResource(originalPath string, v2 bool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		resources, err := legacy.CheckResource(c.Body())
		if err != nil {
			return s.refuse(c, err)
		}
		return s.decide(c, originalPath, resources, func(result any) []byte {
			return legacy.CheckResourceResponse(result, v2)
		})
	}
}

func (s *Server) checkResourceBulk(c *fiber.Ctx) error {
	resources, ids, err := legacy.CheckResourceBulk(c.Body())
	if err != nil {
		return s.refuse(c, err)
	}
	return s.decide(c, "/access/v1/check/resource/bulk", resources, func(result any) []byte {
		return legacy.CheckResourceBulkResponse(result, ids)
	})
}

// checkResourceBulkOperations serves the v1 or v2 bulk/operations routes.
// The decision log records the request's own path and query for them, so
// the access and preview routes stay apart there.
func (s *Server) checkResourceBulkOperations(v2 bool) fiber.Handler {
	parse := legacy.CheckResourceBulkOperations
	if v2 {
		parse = legacy.CheckResourceBulkOperationsV2
	}
	return func(c *fiber.Ctx) error {
		resources, entries, err := parse(c.Body())
		if err != nil {
			return s.refuse(c, err)
		}
		if len(resources) == 0 {
			// A request without a single operation has nothing to decide;
			// the Lua filter answered it without calling OPA.
			return sendJSON(c, http.StatusOK, legacy.CheckResourceBulkOperationsResponse(nil, nil, v2))
		}
		return s.decide(c, c.OriginalURL(), resources, func(result any) []byte {
			return legacy.CheckResourceBulkOperationsResponse(result, entries, v2)
		})
	}
}

func (s *Server) checkFilter(originalPath string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		resources, err := legacy.CheckFilter(lastQuery(c, "resourceType"), lastQuery(c, "operation"))
		if err != nil {
			return s.refuse(c, err)
		}
		return s.check(c, originalPath, resources, legacy.FilterResponse)
	}
}

// lastQuery is the value of the last query parameter named key, "" when
// there is none.
func lastQuery(c *fiber.Ctx, key string) string {
	value := ""
	for k, v := range c.Context().QueryArgs().All() {
		if string(k) == key {
			value = string(v)
		}
	}
	return value
}

// check evaluates the canonical decision for a legacy request and writes
// the response: the body shape builds from the decision, or the authError
// as {"message": ...} with its status when the policy refused the request.
// An undefined decision gets the envelope without a result, and a failed
// evaluation 500, so that both stay visible as they were through Envoy. The
// route is recorded in the decision log as originalPath.
func (s *Server) check(c *fiber.Ctx, originalPath string, resources []legacy.Resource, shape func(result any) []byte) error {
	c.Request().Header.Set(originalPathHeader, originalPath)
	input := legacy.Input(c.GetReqHeaders(), resources)
	result, defined, id, err := s.evaluate(c, []string{"authorize"}, input)
	if err != nil {
		return opaError(c, http.StatusInternalServerError, "internal_error", err.Error())
	}
	if !defined {
		return c.JSON(undefinedEnvelope(id))
	}
	if status, body, refused := legacy.AuthError(result); refused {
		return sendJSON(c, status, body)
	}
	return sendJSON(c, http.StatusOK, shape(result))
}

// refuse writes a request the legacy API rejects before any policy runs:
// 400 with the error's message.
func (s *Server) refuse(c *fiber.Ctx, err *legacy.RequestError) error {
	s.opts.Log.DebugC(c.UserContext(), "legacy request rejected path=%s: %s", c.Path(), err.Message)
	return c.Status(http.StatusBadRequest).JSON(fiber.Map{"message": err.Message})
}

func sendJSON(c *fiber.Ctx, status int, body []byte) error {
	c.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
	return c.Status(status).Send(body)
}
