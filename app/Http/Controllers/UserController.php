<?php

namespace App\Http\Controllers;

use App\Http\Controllers\Controller;
use App\Mail\AuthenticateMail;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use App\Models\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use App\Rules\ReCaptcha;
use Illuminate\Support\Facades\Mail;
use App\Mail\SecondFactor; // Import the necessary class
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\URL;

class UserController extends Controller
{
    public function index() //This is the main page
    {
        return view('Index');
    }
    public function Register() //This is the register page
    {
        return view('register');
    }
    public function Login() //This is the login page
    {
        return view('Log_In');
    }

    public function CreateUser(Request $request) //This is the function to create a new user
    {
        $validacion = Validator::make(
            $request->all(),
            [
                'name' => 'required',
                'email' => 'required|email|unique:users,email',
                'password' => 'required',
                //'g-recaptcha-response' => ['required', new ReCaptcha],
            ]); //This is the validation of the fields

            if($validacion->fails()){
                Log::error('User: ' . $request->email . '  error ' . $validacion->errors()->first() . ' in the register.');
                return redirect('register')->withErrors($validacion);
            } //This is when the validation fails

            $Fisrt_Check = User::All()->count(); //This is to check if the user is the first one to register
            if($Fisrt_Check == 0){//This is when there's no users in the database, the first user will be an admin
                $user = new User();
                $user -> name = $request->name;
                $user -> email = $request->email;
                $user -> password = Hash::make($request->password);
                $user -> role_id = 1;
                $user -> status = false;
                $time = now();

                $url = URL::temporarySignedRoute('AuthenticateUser', now()->addMinutes(10), ['user' => $user->email]); 
                Mail::to($user->email)->send(new AuthenticateMail($user,$url)); 
                
                if($user->save()){
                    Log::info('New Admin User Register: ' . $user->name . ' (' . $user->email . ') , Time:('.$time.')');
                    return redirect()->route('index');
                }
            }else { //This is when there's already a user in the database, the new user will be a normal user
                $user = new User();
                $user -> name = $request->name;
                $user -> email = $request->email;
                $user -> password = Hash::make($request->password);
                $user -> role_id=2;
                $user -> status =false;
                $time = now();

                $url = URL::temporarySignedRoute('AuthenticateUser', now()->addMinutes(10), ['user' => $user->email]); 
                Mail::to($user->email)->send(new AuthenticateMail($user,$url)); 

                if($user->save()){
                    Log::info('New Regular User Register: ' . $user->name . ' (' . $user->email . ') , Time:('.$time.')');
                    return redirect()->route('index');
                }
            }
    }
    public function LoginUser(Request $request)//This is the function to login
    {
        $validacion = Validator::make(
            $request->all(),
            [
                'email' => 'required|email',
                'password' => 'required',
                //'g-recaptcha-response' => ['required', new ReCaptcha],
            ]);//this is the validation of the fields

            if($validacion->fails()){
                Log::error('User: ' . $request->email . '  error ' . $validacion->errors()->first() . ' in the login.');
                return redirect('login')->withErrors($validacion);
            }//This is when the validation fails

            $user = User::where('email', $request->email)->first();//search the user in the database from his email
            if (Hash::check($request->password, $user->password)) {
                if($user->status ==true){
                if($user->role_id != 1) {//check if the user is an admin or not
                    Auth::login($user);
                    Log::info('User: ' . $user->name . ' (' . $user->email . ') has logged in. , Time:('.now().')');
                    return redirect()->route('UserHome');
                } else {//if the user is an admin, go to the second factor of verification
                $verificationCode = mt_rand(100000, 999999);  //generate a random code of six digits
                $code = Hash::make($verificationCode); //hash the code
                $user->two_factor_code = $code; //save the code in the database with the admin wants to get in
                $user->two_factor_expires_at = now()->addMinutes(10); //save the time when the code will expire
                $user->save(); //save the changes in the database
                $time = now();

                $url = URL::temporarySignedRoute('verify', now()->addMinutes(10), ['user' => $user->id]); //create a temporary url with the code
                Log::info('User Admin: ' . $user->name . ' (' . $user->email . ') passed first Authentication Phase. , Time:('.$time.')');
                Mail::to($user->email)->send(new SecondFactor($user,$url,$verificationCode)); //send the email with the code to the admin
                return redirect($url);//go to the page where the admin will put the code
            }}else{
                return back()->withErrors([
                    'email' => 'Please verify your email, you can see it in your inbox.',
                ]); //if the credentials are wrong, return to the login page with an error}
            }}
            return back()->withErrors([
                'email' => 'The provided credentials do not match our records.',
            ]); //if the credentials are wrong, return to the login page with an error
    }

    public function logout(Request $request) //This is the function to logout
    {
        $user=Auth::user(); //get the user
        $time = now();  
        Log::info('User: ' . $user->name . ' (' . $user->email . ') has logged out. , Time:('.$time.')');
        Auth::logout(); //logout the user
        $request->session()->invalidate(); //invalidate the session
        $request->session()->regenerateToken(); //regenerate the token
        return redirect()->route('index'); //return to the main page
    }
    
}
