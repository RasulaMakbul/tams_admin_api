<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Auth;
use Laravel\Sanctum\PersonalAccessToken;
use Illuminate\Support\Facades\Hash;


class AuthController extends Controller
{
    public function register(Request $request)
    {
        $request->validate([
            'name' => 'required|string',
            'email' => 'required|email|unique:users,email',
            'password' => 'required|min:6',
        ]);

        // Check if the email already exists
        if (User::where('email', $request->email)->exists()) {
            return response()->json(['message' => 'Email address already registered'], 422);
        }

        // Create a new user
        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => bcrypt($request->password),
        ]);

        return response()->json(['message' => 'User registered successfully'], 201);
    }

    public function login(Request $request)
    {
        $request->validate([
            'email' => 'required|string|email',
            'password' => 'required|string',
        ]);

        // Attempt to log in the user
        if (Auth::attempt(['email' => $request->email, 'password' => $request->password])) {
            $user = Auth::user();

            // Check if the user's role_as is 1 (admin)
            if ($user->role_as == 1) {
                // Create a token for the authenticated user
                $token = $user->createToken('authToken')->plainTextToken;

                return response()->json(['token' => $token, 'message' => 'Login successful']);
            } else {
                return response()->json(['message' => 'You do not have permission to log in.'], 403);
            }
        } else {
            return response()->json(['message' => 'Invalid credentials'], 401);
        }
    }

    public function logout(Request $request)
    {
        // Revoke the user's current token...
        $request->user()->currentAccessToken()->delete();

        return response()->json(['message' => 'Logout successful']);
    }

    public function getUserTokens(Request $request)
    {
        $tokens = $request->user()->tokens;

        return response()->json(['tokens' => $tokens]);
    }
}
