<?php

namespace App\Http\Controllers;

use App\Http\Controllers\Controller;
use App\Mail\SecondFactor;
use Illuminate\Http\Request;
use App\Models\User;
use App\Rules\ReCaptcha;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\URL;

class AuthUserController extends Controller
{
    public function verify()
    {
        return view('VerifyView');
    }
    public function verifyTwoFactor(Request $request)
    {
        
        $request->validate([
            'verification_code' => 'required|digits:6',
            'g-recaptcha-response' => ['required', new ReCaptcha],
        ]);

        $user = User::where('id', $request->user)->first();

        if (Hash::check($request->verification_code,$user->two_factor_code) && $user->two_factor_expires_at > now()) {
            $chnguser = User::where('id', $user->id)->first();
            $chnguser->two_factor_code = null;
            $chnguser->two_factor_expires_at = null;
            $chnguser->status = true;
            $chnguser->save();
            $time = now();

            Auth::login($user);
            Log::info('User Admin: ' . $user->name . ' (' . $user->email . ') passed the second Authentication Phase.');
            Log::info('User Admin: ' . $user->name . ' (' . $user->email . '), Time:('.$time.') has logged in.');
            // Puedes redirigir al usuario a su dashboard u otra página
            return redirect()->route('AdminHome');
        } else {
            // Código incorrecto, muestra un mensaje de error
            Log::error('User Admin: ' . $user->name . ' (' . $user->email . ') failed the second Authentication Phase.');
            return back()->withErrors(['verification_code' => 'incorrect code']);
        }
    }
    public function AuthenticateMail(Request $request)
    {
        $user = User::where('email', $request->query('user'))->first();
        if ($user) {
            $user->status = true;
            $user->save();
        } 
        return redirect()->route('index');
    }
    public function ResendEmailForLoginAdmin(Request $request)
    {
        $user = User::where('id', $request->user)->first();
        $verificationCode = mt_rand(100000, 999999);
        $code = Hash::make($verificationCode);
        $user->two_factor_code = $code;
        $user->two_factor_expires_at = now()->addMinutes(10);  
        if ($user->save()) {
            $url = URL::temporarySignedRoute('verify', now()->addMinutes(10), ['user' => $user->id]); //create a temporary url with the code
            Log::info('User Admin: ' . $user->name . ' (' . $user->email . ') passed first Authentication Phase. , Time:('.now().')');
            Mail::to($user->email)->send(new SecondFactor($user, $url,$verificationCode));
            return redirect($url);
        }
    }
    public function test (Request $request)
    {
        $text = "arremangala arrempujala";
        return $text;
    }
}
