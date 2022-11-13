<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller {
    public function register(Request $request) {
        $validator = Validator::make($request->all(), [
            'name'     => 'required|string|max:255',
            'email'    => 'required|string|email|max:100|unique:users,email',
            'password' => 'required|string|min:8',
        ]);

        if ($validator->fails()) {
            return response()->json(['validation_errors' => $validator->messages()]);
        } else {
            $user = User::create([
                'name'     => $request->name,
                'email'    => $request->email,
                'password' => Hash::make($request->password),
            ]);

            $token = $user->createToken($user->email . '_Token')->plainTextToken;
            return response()->json([
                'status'   => 200,
                'username' => $user->name,
                'token'    => $token,
                'message'  => 'User created successfully',

            ]);

        }
    }
    public function login(Request $request) {
        $validator = Validator::make($request->all(), [
            'email'    => 'required|string|email|max:100',
            'password' => 'required|string',
        ]);

        if ($validator->fails()) {
            return response()->json(['validation_errors' => $validator->messages()]);
        } else {
            $user = User::where('email', $request->email)->first();
            if (!$user || !Hash::check($request->password, $user->password)) {
                return response()->json([
                    'status'  => 401,
                    'message' => 'Usuario o contraseña incorrectos',
                ]);

            } else {
                $token = $user->createToken($user->email . '_Token')->plainTextToken;
                return response()->json([
                    'status'   => 200,
                    'username' => $user->name,
                    'token'    => $token,
                    'message'  => 'User logged in successfully',

                ]);
            }
        }
    }
}
