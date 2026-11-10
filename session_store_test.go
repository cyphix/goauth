package goauth

import (
	"testing"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func TestSessionStoreNamespaceAndLifecycle(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: -1})
	t.Cleanup(func() { _ = rdb.Close() })
	a, err := New(Config{DB: newTestDB(t), Redis: rdb})
	require.NoError(t, err)
	store := a.sessions.Store.(scs.CtxStore)
	iterable := a.sessions.Store.(scs.IterableCtxStore)
	ctx := t.Context()

	data, found, err := store.FindCtx(ctx, "missing")
	require.NoError(t, err)
	require.False(t, found)
	require.Nil(t, data)
	sessions, err := iterable.AllCtx(ctx)
	require.NoError(t, err)
	require.Empty(t, sessions)

	require.NoError(t, mr.Set("other:session:token", "unrelated"))
	require.NoError(t, store.CommitCtx(ctx, "token", []byte("first"), time.Now().Add(time.Minute)))
	value, err := mr.Get("goauth:session:token")
	require.NoError(t, err)
	require.Equal(t, "first", value)
	require.False(t, mr.Exists("scs:session:token"))
	require.Positive(t, mr.TTL("goauth:session:token"))

	require.NoError(t, store.CommitCtx(ctx, "token", []byte("updated"), time.Now().Add(2*time.Minute)))
	data, found, err = store.FindCtx(ctx, "token")
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, []byte("updated"), data)
	sessions, err = iterable.AllCtx(ctx)
	require.NoError(t, err)
	require.Equal(t, map[string][]byte{"token": []byte("updated")}, sessions)

	mr.FastForward(3 * time.Minute)
	_, found, err = store.FindCtx(ctx, "token")
	require.NoError(t, err)
	require.False(t, found)
	sessions, err = iterable.AllCtx(ctx)
	require.NoError(t, err)
	require.Empty(t, sessions)

	require.NoError(t, store.CommitCtx(ctx, "token", []byte("last"), time.Now().Add(time.Minute)))
	require.NoError(t, store.DeleteCtx(ctx, "token"))
	require.NoError(t, store.DeleteCtx(ctx, "missing"))
	require.False(t, mr.Exists("goauth:session:token"))
	require.True(t, mr.Exists("other:session:token"))

	mr.SetError("ERR unavailable")
	_, _, err = store.FindCtx(ctx, "token")
	require.ErrorContains(t, err, "unavailable")
	require.ErrorContains(t, store.CommitCtx(ctx, "token", nil, time.Now().Add(time.Minute)), "unavailable")
	require.ErrorContains(t, store.DeleteCtx(ctx, "token"), "unavailable")
	_, err = iterable.AllCtx(ctx)
	require.ErrorContains(t, err, "unavailable")
}
