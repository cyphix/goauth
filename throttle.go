package goauth

import (
	"context"
	"errors"
	"strconv"
	"time"
)

const (
	throttlePrefix             = "goauth:throttle:"
	throttleWindow             = 5 * time.Minute
	throttleMaxAttempts        = 10
	throttleAccountMaxAttempts = 30
	throttleIPMaxAttempts      = 100
)

// throttleAllow records a login attempt for key and reports whether the
// attempt may proceed. Redis failures are surfaced (fail closed would lock
// everyone out on a Redis blip; fail open would defeat the throttle — we
// return the error and let the request fail loudly instead).
func (a *Auth) throttleAllow(ctx context.Context, key string, max int64) (bool, error) {
	redisKey := throttlePrefix + key
	count, err := a.redis.Incr(ctx, redisKey).Result()
	if err != nil {
		return false, err
	}
	if count == 1 {
		if err := a.redis.Expire(ctx, redisKey, throttleWindow).Err(); err != nil {
			return false, err
		}
	}
	return count <= max, nil
}

func (a *Auth) loginAccountKey(identifier string) (string, error) {
	user, err := a.FindUserByIdentifier(identifier)
	if err == nil {
		return "uid:" + strconv.FormatUint(uint64(user.ID), 10), nil
	}
	if errors.Is(err, ErrNotFound) {
		return "name:" + NormalizeUsername(identifier), nil
	}
	return "", err
}

type loginThrottle struct{ ip, account, accountIP string }

func newLoginThrottle(account, ip string) loginThrottle {
	return loginThrottle{
		ip:        "ip:" + ip,
		account:   "acct:" + account,
		accountIP: "acctip:" + ip + "|" + account,
	}
}

func (a *Auth) loginThrottleAllow(ctx context.Context, t loginThrottle) (bool, error) {
	allowed, err := a.throttleAllow(ctx, t.ip, throttleIPMaxAttempts)
	if err != nil || !allowed {
		return allowed, err
	}
	allowed, err = a.throttleAllow(ctx, t.account, throttleAccountMaxAttempts)
	if err != nil || !allowed {
		return allowed, err
	}
	return a.throttleAllow(ctx, t.accountIP, throttleMaxAttempts)
}

// throttleReset clears the attempt counter after a successful login.
func (a *Auth) throttleReset(ctx context.Context, key string) {
	if err := a.redis.Del(ctx, throttlePrefix+key).Err(); err != nil {
		a.logger.Warn().Err(err).Msg("failed to reset login throttle")
	}
}
