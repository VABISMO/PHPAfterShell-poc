<?php

use Illuminate\Support\Facades\Route;

/*
 * Lab routes for the phpAfterShell Laravel target.
 *
 * The middleware below represents the very common class of Laravel
 * packages that use NATIVE PHP sessions (carts, session-based auth
 * bridges, ...). It starts a session and stores one user-submitted
 * field - exactly the two things the chain needs from a real target.
 * It reports nothing, provides no endpoint and no diagnostic: the
 * exploit still learns only from natural HTTP behaviour.
 */
$labNativeSession = function ($request, $next) {
    if (session_status() === PHP_SESSION_NONE && !headers_sent()) {
        session_start();
    }
    return $next($request);
};

// consumer: any page that runs session_start() materialises the
// injected object on decode; its destructor fires at shutdown
Route::get('/', function () {
    return view('welcome');
})->middleware($labNativeSession);

// carrier payload store: ordinary app behaviour (form field -> session)
Route::post('/bio', function () {
    $_SESSION['bio'] = (string) request('bio');
    return 'stored:' . strlen($_SESSION['bio']);
})->middleware($labNativeSession);
