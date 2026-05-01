-- ACP Redis Lua Rate Limiter
-- ===========================
-- Atomic token-bucket / fixed-window rate limiter.
-- Guarantees O(1) with no race conditions.
--
-- KEYS[1]  : rate key  (e.g. "rate:agent:{agent_id}" or "rate:token:{jti}")
-- ARGV[1]  : limit     (integer, max requests allowed in window)
-- ARGV[2]  : window    (integer, window duration in seconds)
-- ARGV[3]  : tokens    (integer, token cost of this request — default 1)
--
-- Returns:
--   count  (integer) : current count after increment   (> limit means DENIED)
--   or
--   0                : denied (count already exceeded)

local key    = KEYS[1]
local limit  = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local cost   = tonumber(ARGV[3]) or 1

-- Atomically increment
local count = redis.call('INCRBY', key, cost)

-- On first increment, set expiry (TTL = window seconds)
if count == cost then
    redis.call('EXPIRE', key, window)
end

-- Deny if over limit
if count > limit then
    return 0
end

return count
