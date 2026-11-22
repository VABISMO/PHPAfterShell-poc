<?php

namespace App\Http\Middleware;

use Closure;

/**
 * Lab middleware for the phpAfterShell Laravel target.
 *
 * Represents the very common class of Laravel packages that use NATIVE
 * PHP sessions (carts, session-based auth bridges, ...): it starts a
 * session on every request. It reports nothing and provides no
 * endpoint or diagnostic - the exploit still learns only from natural
 * HTTP behaviour, exactly as against any other target.
 *
 * Laravel requires middleware to be a CLASS (Route::middleware casts
 * each entry to string), so this cannot be a closure.
 */
class NativeSession
{
    public function handle($request, Closure $next)
    {
        if (session_status() === PHP_SESSION_NONE && !headers_sent()) {
            session_start();
        }

        return $next($request);
    }
}
