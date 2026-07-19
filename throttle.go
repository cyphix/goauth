package goauth

import (
	"context"
	"time"
)

const (
	throttlePrefix      = "goauth:throttle:"
	throttleMaxAttempts = 10
	throttleWindow      = 5 * time.Minute
)

// throttleAllow records a login attempt for key and reports whether the
// attempt may proceed. Redis failures are surfaced (fail closed would lock
// everyone out on a Redis blip; fail open would defeat the throttle — we
// return the error and let the request fail loudly instead).
func (a *Auth) throttleAllow(ctx context.Context, key string) (bool, error) {
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
	return count <= throttleMaxAttempts, nil
}

// throttleReset clears the attempt counter after a successful login.
func (a *Auth) throttleReset(ctx context.Context, key string) {
	if err := a.redis.Del(ctx, throttlePrefix+key).Err(); err != nil {
		a.logger.Warn().Err(err).Msg("failed to reset login throttle")
	}
}
