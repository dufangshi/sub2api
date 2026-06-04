package admin

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/Wei-Shaw/sub2api/internal/pkg/pagination"
	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/pkg/usagestats"
	"github.com/Wei-Shaw/sub2api/internal/service"

	"github.com/gin-gonic/gin"
)

const (
	remoteCodexKeyNamePrefix  = "remote-codex:sandbox:"
	remoteCodexUserNotePrefix = "remote-codex:user:"
	defaultRemoteCodexLimit   = 100
	maxRemoteCodexLimit       = 1000
)

type RemoteCodexIntegrationHandler struct {
	adminService         service.AdminService
	apiKeyService        *service.APIKeyService
	usageService         *service.UsageService
	userRepo             service.UserRepository
	groupRepo            service.GroupRepository
	userSubRepo          service.UserSubscriptionRepository
	authCacheInvalidator service.APIKeyAuthCacheInvalidator
}

func NewRemoteCodexIntegrationHandler(
	adminService service.AdminService,
	apiKeyService *service.APIKeyService,
	usageService *service.UsageService,
	userRepo service.UserRepository,
	groupRepo service.GroupRepository,
	userSubRepo service.UserSubscriptionRepository,
	authCacheInvalidator service.APIKeyAuthCacheInvalidator,
) *RemoteCodexIntegrationHandler {
	return &RemoteCodexIntegrationHandler{
		adminService:         adminService,
		apiKeyService:        apiKeyService,
		usageService:         usageService,
		userRepo:             userRepo,
		groupRepo:            groupRepo,
		userSubRepo:          userSubRepo,
		authCacheInvalidator: authCacheInvalidator,
	}
}

type remoteCodexEnsureUserRequest struct {
	ExternalID  string   `json:"externalId"`
	Email       string   `json:"email"`
	DisplayName *string  `json:"displayName"`
	Balance     *float64 `json:"balance"`
	Concurrency *int     `json:"concurrency"`
	RPMLimit    *int     `json:"rpm_limit"`
}

type remoteCodexEnsureBalanceRequest struct {
	MinimumBalance float64 `json:"minimumBalance"`
	TargetBalance  float64 `json:"targetBalance"`
	Notes          string  `json:"notes"`
}

type remoteCodexEnsureKeyRequest struct {
	ExternalID    string   `json:"externalId"`
	SandboxID     string   `json:"sandboxId"`
	GroupID       *int64   `json:"group_id"`
	Quota         *float64 `json:"quota"`
	ExpiresInDays *int     `json:"expires_in_days"`
	RateLimit5h   *float64 `json:"rate_limit_5h"`
	RateLimit1d   *float64 `json:"rate_limit_1d"`
	RateLimit7d   *float64 `json:"rate_limit_7d"`
	IPWhitelist   []string `json:"ip_whitelist"`
	IPBlacklist   []string `json:"ip_blacklist"`
}

type remoteCodexRotateKeyRequest struct {
	SandboxID     string   `json:"sandboxId"`
	GroupID       *int64   `json:"group_id"`
	Quota         *float64 `json:"quota"`
	ExpiresInDays *int     `json:"expires_in_days"`
	RateLimit5h   *float64 `json:"rate_limit_5h"`
	RateLimit1d   *float64 `json:"rate_limit_1d"`
	RateLimit7d   *float64 `json:"rate_limit_7d"`
	IPWhitelist   []string `json:"ip_whitelist"`
	IPBlacklist   []string `json:"ip_blacklist"`
}

type remoteCodexKeyResponse struct {
	ExternalKeyID string  `json:"externalKeyId"`
	KeyCiphertext *string `json:"keyCiphertext,omitempty"`
	Key           *string `json:"key,omitempty"`
	UserID        int64   `json:"user_id"`
	GroupID       *int64  `json:"group_id"`
	Status        string  `json:"status"`
	Created       bool    `json:"created"`
	Rotated       bool    `json:"rotated,omitempty"`
}

type remoteCodexUsageEvent struct {
	EventID       string  `json:"eventId"`
	ExternalKeyID string  `json:"externalKeyId"`
	Model         string  `json:"model"`
	InputTokens   int     `json:"inputTokens,omitempty"`
	OutputTokens  int     `json:"outputTokens,omitempty"`
	CachedTokens  int     `json:"cachedTokens,omitempty"`
	CostUSD       float64 `json:"costUsd,omitempty"`
	Currency      string  `json:"currency,omitempty"`
	OccurredAt    string  `json:"occurredAt,omitempty"`
	UserID        int64   `json:"user_id,omitempty"`
	GroupID       *int64  `json:"group_id,omitempty"`
	SandboxID     string  `json:"sandboxId,omitempty"`
}

type remoteCodexUsageExportResponse struct {
	Events     []remoteCodexUsageEvent `json:"events"`
	NextCursor *string                 `json:"nextCursor"`
}

type remoteCodexUsageCursor struct {
	Page int `json:"page"`
}

func (h *RemoteCodexIntegrationHandler) EnsureUser(c *gin.Context) {
	var req remoteCodexEnsureUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "Invalid request: "+err.Error())
		return
	}
	req.Email = strings.TrimSpace(req.Email)
	req.ExternalID = strings.TrimSpace(req.ExternalID)
	if req.Email == "" {
		response.BadRequest(c, "email is required")
		return
	}
	if req.ExternalID == "" {
		response.BadRequest(c, "externalId is required")
		return
	}

	user, err := h.userRepo.GetByEmail(c.Request.Context(), req.Email)
	if err != nil && !errors.Is(err, service.ErrUserNotFound) {
		response.ErrorFrom(c, err)
		return
	}
	created := false
	if user == nil {
		password, err := generateRemoteCodexPassword()
		if err != nil {
			response.ErrorFrom(c, err)
			return
		}
		concurrency := 0
		if req.Concurrency != nil {
			concurrency = *req.Concurrency
		}
		rpmLimit := 0
		if req.RPMLimit != nil {
			rpmLimit = *req.RPMLimit
		}
		username := req.Email
		if req.DisplayName != nil && strings.TrimSpace(*req.DisplayName) != "" {
			username = strings.TrimSpace(*req.DisplayName)
		}
		user, err = h.adminService.CreateUser(c.Request.Context(), &service.CreateUserInput{
			Email:       req.Email,
			Password:    password,
			Username:    username,
			Notes:       remoteCodexUserNotePrefix + req.ExternalID,
			Balance:     req.Balance,
			Concurrency: concurrency,
			RPMLimit:    rpmLimit,
		})
		if err != nil {
			response.ErrorFrom(c, err)
			return
		}
		created = true
	}

	c.JSON(http.StatusOK, gin.H{
		"externalUserId": strconv.FormatInt(user.ID, 10),
		"id":             strconv.FormatInt(user.ID, 10),
		"user_id":        user.ID,
		"email":          user.Email,
		"balance":        user.Balance,
		"created":        created,
	})
}

func (h *RemoteCodexIntegrationHandler) EnsureUserBalance(c *gin.Context) {
	userID, ok := parsePositiveInt64Param(c, "user_id")
	if !ok {
		return
	}
	var req remoteCodexEnsureBalanceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "Invalid request: "+err.Error())
		return
	}
	if req.MinimumBalance < 0 {
		response.BadRequest(c, "minimumBalance must be non-negative")
		return
	}
	if req.TargetBalance <= 0 {
		response.BadRequest(c, "targetBalance must be positive")
		return
	}
	if req.TargetBalance < req.MinimumBalance {
		response.BadRequest(c, "targetBalance must be greater than or equal to minimumBalance")
		return
	}

	user, err := h.userRepo.GetByID(c.Request.Context(), userID)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	previousBalance := user.Balance
	adjusted := false
	if user.Balance < req.MinimumBalance {
		notes := strings.TrimSpace(req.Notes)
		if notes == "" {
			notes = "remote-codex automatic balance refill"
		}
		user, err = h.adminService.UpdateUserBalance(c.Request.Context(), userID, req.TargetBalance, "set", notes)
		if err != nil {
			response.ErrorFrom(c, err)
			return
		}
		adjusted = true
	}

	c.JSON(http.StatusOK, gin.H{
		"externalUserId":  strconv.FormatInt(user.ID, 10),
		"id":              strconv.FormatInt(user.ID, 10),
		"user_id":         user.ID,
		"balance":         user.Balance,
		"previousBalance": previousBalance,
		"adjusted":        adjusted,
	})
}

func (h *RemoteCodexIntegrationHandler) EnsureSandboxKey(c *gin.Context) {
	userID, ok := parsePositiveInt64Param(c, "user_id")
	if !ok {
		return
	}
	var req remoteCodexEnsureKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "Invalid request: "+err.Error())
		return
	}
	sandboxID := firstNonEmptyRemoteCodexValue(req.SandboxID, req.ExternalID)
	if sandboxID == "" {
		response.BadRequest(c, "sandboxId or externalId is required")
		return
	}

	if err := h.ensureGroupAccess(c.Request.Context(), userID, req.GroupID); err != nil {
		response.ErrorFrom(c, err)
		return
	}

	existing, err := h.findSandboxKey(c.Request.Context(), userID, sandboxID)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	if existing != nil {
		c.JSON(http.StatusOK, keyResponse(existing, nil, false, false))
		return
	}

	key, err := h.createSandboxKey(c.Request.Context(), userID, sandboxID, remoteCodexCreateKeyOptions{
		GroupID:       req.GroupID,
		Quota:         req.Quota,
		ExpiresInDays: req.ExpiresInDays,
		RateLimit5h:   req.RateLimit5h,
		RateLimit1d:   req.RateLimit1d,
		RateLimit7d:   req.RateLimit7d,
		IPWhitelist:   req.IPWhitelist,
		IPBlacklist:   req.IPBlacklist,
	})
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	c.JSON(http.StatusOK, keyResponse(key, &key.Key, true, false))
}

func (h *RemoteCodexIntegrationHandler) RotateSandboxKey(c *gin.Context) {
	userID, ok := parsePositiveInt64Param(c, "user_id")
	if !ok {
		return
	}
	keyID, ok := parsePositiveInt64Param(c, "key_id")
	if !ok {
		return
	}
	var req remoteCodexRotateKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "Invalid request: "+err.Error())
		return
	}
	oldKey, err := h.apiKeyService.GetByID(c.Request.Context(), keyID)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	if oldKey.UserID != userID {
		response.Forbidden(c, "API key does not belong to user")
		return
	}

	groupID := coalesceInt64Ptr(req.GroupID, oldKey.GroupID)
	if err := h.ensureGroupAccess(c.Request.Context(), userID, groupID); err != nil {
		response.ErrorFrom(c, err)
		return
	}

	sandboxID := strings.TrimSpace(req.SandboxID)
	if sandboxID == "" {
		sandboxID = sandboxIDFromKeyName(oldKey.Name)
	}
	if sandboxID == "" {
		response.BadRequest(c, "sandboxId is required")
		return
	}

	newKey, err := h.createSandboxKey(c.Request.Context(), userID, sandboxID, remoteCodexCreateKeyOptions{
		GroupID:       groupID,
		Quota:         req.Quota,
		ExpiresInDays: req.ExpiresInDays,
		RateLimit5h:   req.RateLimit5h,
		RateLimit1d:   req.RateLimit1d,
		RateLimit7d:   req.RateLimit7d,
		IPWhitelist:   req.IPWhitelist,
		IPBlacklist:   req.IPBlacklist,
	})
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	if err := h.disableKey(c.Request.Context(), oldKey); err != nil {
		response.ErrorFrom(c, err)
		return
	}
	c.JSON(http.StatusOK, keyResponse(newKey, &newKey.Key, true, true))
}

func (h *RemoteCodexIntegrationHandler) RevokeSandboxKey(c *gin.Context) {
	userID, ok := parsePositiveInt64Param(c, "user_id")
	if !ok {
		return
	}
	keyID, ok := parsePositiveInt64Param(c, "key_id")
	if !ok {
		return
	}
	key, err := h.apiKeyService.GetByID(c.Request.Context(), keyID)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	if key.UserID != userID {
		response.Forbidden(c, "API key does not belong to user")
		return
	}
	if err := h.disableKey(c.Request.Context(), key); err != nil {
		response.ErrorFrom(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"externalKeyId": strconv.FormatInt(key.ID, 10),
		"id":            strconv.FormatInt(key.ID, 10),
		"status":        service.StatusAPIKeyDisabled,
	})
}

func (h *RemoteCodexIntegrationHandler) ExportUsage(c *gin.Context) {
	limit := parseLimit(c.DefaultQuery("limit", ""))
	page := 1
	if cursor := strings.TrimSpace(c.Query("cursor")); cursor != "" {
		decoded, err := decodeUsageCursor(cursor)
		if err != nil {
			response.BadRequest(c, "Invalid cursor")
			return
		}
		page = decoded.Page
	}

	filters, ok := parseUsageFilters(c)
	if !ok {
		return
	}
	records, result, err := h.usageService.ListWithFilters(c.Request.Context(), pagination.PaginationParams{
		Page:      page,
		PageSize:  limit,
		SortBy:    "created_at",
		SortOrder: pagination.SortOrderAsc,
	}, filters)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}

	events := make([]remoteCodexUsageEvent, 0, len(records))
	for i := range records {
		events = append(events, usageEventFromLog(&records[i]))
	}

	var nextCursor *string
	if result != nil && page < result.Pages && len(events) > 0 {
		value := encodeUsageCursor(remoteCodexUsageCursor{Page: page + 1})
		nextCursor = &value
	}
	c.JSON(http.StatusOK, remoteCodexUsageExportResponse{
		Events:     events,
		NextCursor: nextCursor,
	})
}

type remoteCodexCreateKeyOptions struct {
	GroupID       *int64
	Quota         *float64
	ExpiresInDays *int
	RateLimit5h   *float64
	RateLimit1d   *float64
	RateLimit7d   *float64
	IPWhitelist   []string
	IPBlacklist   []string
}

func (h *RemoteCodexIntegrationHandler) createSandboxKey(ctx context.Context, userID int64, sandboxID string, opts remoteCodexCreateKeyOptions) (*service.APIKey, error) {
	req := service.CreateAPIKeyRequest{
		Name:          remoteCodexKeyName(sandboxID),
		GroupID:       opts.GroupID,
		ExpiresInDays: opts.ExpiresInDays,
		IPWhitelist:   opts.IPWhitelist,
		IPBlacklist:   opts.IPBlacklist,
	}
	if opts.Quota != nil {
		req.Quota = *opts.Quota
	}
	if opts.RateLimit5h != nil {
		req.RateLimit5h = *opts.RateLimit5h
	}
	if opts.RateLimit1d != nil {
		req.RateLimit1d = *opts.RateLimit1d
	}
	if opts.RateLimit7d != nil {
		req.RateLimit7d = *opts.RateLimit7d
	}
	return h.apiKeyService.Create(ctx, userID, req)
}

func (h *RemoteCodexIntegrationHandler) ensureGroupAccess(ctx context.Context, userID int64, groupID *int64) error {
	if groupID == nil || *groupID <= 0 {
		return nil
	}
	user, err := h.userRepo.GetByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("get user: %w", err)
	}
	if !user.IsActive() {
		return infraerrors.Forbidden("REMOTE_CODEX_USER_DISABLED", "user is disabled")
	}

	group, err := h.groupRepo.GetByID(ctx, *groupID)
	if err != nil {
		return fmt.Errorf("get group: %w", err)
	}
	if !group.IsActive() {
		return infraerrors.BadRequest("REMOTE_CODEX_GROUP_INACTIVE", "group is not active")
	}

	if group.IsSubscriptionType() {
		if _, err := h.userSubRepo.GetActiveByUserIDAndGroupID(ctx, userID, group.ID); err != nil {
			if errors.Is(err, service.ErrSubscriptionNotFound) {
				return infraerrors.BadRequest("REMOTE_CODEX_SUBSCRIPTION_REQUIRED", "active subscription is required for this group")
			}
			return fmt.Errorf("get active subscription: %w", err)
		}
		return nil
	}

	if group.IsExclusive {
		if err := h.userRepo.AddGroupToAllowedGroups(ctx, userID, group.ID); err != nil {
			return fmt.Errorf("allow user group: %w", err)
		}
		if h.authCacheInvalidator != nil {
			h.authCacheInvalidator.InvalidateAuthCacheByUserID(ctx, userID)
		}
	}
	return nil
}

func (h *RemoteCodexIntegrationHandler) disableKey(ctx context.Context, key *service.APIKey) error {
	if key == nil {
		return service.ErrAPIKeyNotFound
	}
	disabled := service.StatusAPIKeyDisabled
	_, err := h.apiKeyService.Update(ctx, key.ID, key.UserID, service.UpdateAPIKeyRequest{
		Status:      &disabled,
		IPWhitelist: append([]string(nil), key.IPWhitelist...),
		IPBlacklist: append([]string(nil), key.IPBlacklist...),
	})
	return err
}

func (h *RemoteCodexIntegrationHandler) findSandboxKey(ctx context.Context, userID int64, sandboxID string) (*service.APIKey, error) {
	keys, _, err := h.adminService.GetUserAPIKeys(ctx, userID, 1, 1000, "created_at", "desc")
	if err != nil {
		return nil, err
	}
	targetName := remoteCodexKeyName(sandboxID)
	for i := range keys {
		if keys[i].Name == targetName && keys[i].Status == service.StatusAPIKeyActive {
			return &keys[i], nil
		}
	}
	return nil, nil
}

func keyResponse(key *service.APIKey, secret *string, created bool, rotated bool) remoteCodexKeyResponse {
	resp := remoteCodexKeyResponse{
		ExternalKeyID: strconv.FormatInt(key.ID, 10),
		UserID:        key.UserID,
		GroupID:       key.GroupID,
		Status:        key.Status,
		Created:       created,
		Rotated:       rotated,
	}
	if secret != nil {
		resp.KeyCiphertext = secret
		resp.Key = secret
	}
	return resp
}

func usageEventFromLog(log *service.UsageLog) remoteCodexUsageEvent {
	model := strings.TrimSpace(log.RequestedModel)
	if model == "" {
		model = log.Model
	}
	return remoteCodexUsageEvent{
		EventID:       strconv.FormatInt(log.ID, 10),
		ExternalKeyID: strconv.FormatInt(log.APIKeyID, 10),
		Model:         model,
		InputTokens:   log.InputTokens,
		OutputTokens:  log.OutputTokens,
		CachedTokens:  log.CacheCreationTokens + log.CacheReadTokens,
		CostUSD:       log.ActualCost,
		Currency:      "USD",
		OccurredAt:    log.CreatedAt.UTC().Format(time.RFC3339Nano),
		UserID:        log.UserID,
		GroupID:       log.GroupID,
		SandboxID:     sandboxIDFromKeyName(apiKeyName(log)),
	}
}

func apiKeyName(log *service.UsageLog) string {
	if log != nil && log.APIKey != nil {
		return log.APIKey.Name
	}
	return ""
}

func parseUsageFilters(c *gin.Context) (usagestats.UsageLogFilters, bool) {
	var filters usagestats.UsageLogFilters
	filters.ExactTotal = true

	var ok bool
	if filters.UserID, ok = parseOptionalInt64Query(c, "user_id"); !ok {
		return filters, false
	}
	if filters.APIKeyID, ok = parseOptionalInt64Query(c, "api_key_id"); !ok {
		return filters, false
	}
	if filters.GroupID, ok = parseOptionalInt64Query(c, "group_id"); !ok {
		return filters, false
	}
	if filters.AccountID, ok = parseOptionalInt64Query(c, "account_id"); !ok {
		return filters, false
	}
	filters.Model = strings.TrimSpace(c.Query("model"))
	if raw := strings.TrimSpace(c.Query("start")); raw != "" {
		value, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			response.BadRequest(c, "Invalid start")
			return filters, false
		}
		filters.StartTime = &value
	}
	if raw := strings.TrimSpace(c.Query("end")); raw != "" {
		value, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			response.BadRequest(c, "Invalid end")
			return filters, false
		}
		filters.EndTime = &value
	}
	return filters, true
}

func parseOptionalInt64Query(c *gin.Context, name string) (int64, bool) {
	raw := strings.TrimSpace(c.Query(name))
	if raw == "" {
		return 0, true
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value <= 0 {
		response.BadRequest(c, "Invalid "+name)
		return 0, false
	}
	return value, true
}

func remoteCodexKeyName(sandboxID string) string {
	return remoteCodexKeyNamePrefix + strings.TrimSpace(sandboxID)
}

func sandboxIDFromKeyName(name string) string {
	name = strings.TrimSpace(name)
	if strings.HasPrefix(name, remoteCodexKeyNamePrefix) {
		return strings.TrimPrefix(name, remoteCodexKeyNamePrefix)
	}
	return ""
}

func generateRemoteCodexPassword() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate random password: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func parsePositiveInt64Param(c *gin.Context, name string) (int64, bool) {
	value, err := strconv.ParseInt(c.Param(name), 10, 64)
	if err != nil || value <= 0 {
		response.BadRequest(c, "Invalid "+name)
		return 0, false
	}
	return value, true
}

func parseLimit(raw string) int {
	if strings.TrimSpace(raw) == "" {
		return defaultRemoteCodexLimit
	}
	limit, err := strconv.Atoi(raw)
	if err != nil || limit <= 0 {
		return defaultRemoteCodexLimit
	}
	if limit > maxRemoteCodexLimit {
		return maxRemoteCodexLimit
	}
	return limit
}

func encodeUsageCursor(cursor remoteCodexUsageCursor) string {
	payload, _ := json.Marshal(cursor)
	return base64.RawURLEncoding.EncodeToString(payload)
}

func decodeUsageCursor(raw string) (remoteCodexUsageCursor, error) {
	payload, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return remoteCodexUsageCursor{}, err
	}
	var cursor remoteCodexUsageCursor
	if err := json.Unmarshal(payload, &cursor); err != nil {
		return remoteCodexUsageCursor{}, err
	}
	if cursor.Page < 1 {
		cursor.Page = 1
	}
	return cursor, nil
}

func firstNonEmptyRemoteCodexValue(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func coalesceInt64Ptr(values ...*int64) *int64 {
	for _, value := range values {
		if value != nil {
			return value
		}
	}
	return nil
}
