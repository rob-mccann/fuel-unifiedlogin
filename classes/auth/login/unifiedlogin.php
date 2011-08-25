<?php
namespace UnifiedLogin;

/**
 * Unified login driver. Sits atop other auth drivers to allow users to 'link' multiple accounts to one user.
 *
 * @package     UnifiedLogin
 */
class Auth_Login_UnifiedLogin extends \Auth\Auth_Login_SimpleAuth {

	public static function _init()
	{
		parent::_init();
		\Config::load('unifiedlogin', true);
		
		
	}

	/**
	 * Login user
	 *
	 * @param   string
	 * @param   string
	 * @param   string
	 * @return  bool
	 */
	public function send($type, $callbackUri, $params = array())
	{
		\Fuel::add_module('users');
		switch(strtolower($type)){
			case 'facebook':
				\Fuel::add_package('facebook');
				$perms = array('email','offline_access');	
				
				if(is_array($params))
				{
					if( $params['scope'] )
					{
						foreach($params['scope'] as $p)
						{
							$perms[] = $p;
						}
					}					
				}		
		
				//always go to facebook incase required permissions have changed. Would need to store permissions locally and monitor for changes to make this more efficient
				\Facebook\Fb::require_auth(array(
					'scope' => $perms,
					'redirect_uri'  => $callbackUri));
				break;
			case 'twitter':
				\Fuel::add_package('twitter');
				if ( ! \Twitter\Tweet::instance()->logged_in() )
				{
					\Twitter\Tweet::instance()->set_callback($callbackUri);
					\Twitter\Tweet::instance()->login();
				}
				else
				{
					\Response::redirect($callbackUri);
				}
				break;
			case 'google':
				break;
			case 'openid':
				break;
			case 'auth':
				return parent::login($username, $password);
				break;	
		}		
	}
	
	public function callback($type, $finaliseUri, $bindto = null)
	{
		\Fuel::add_module('users');
		switch(strtolower($type)){
			case 'facebook':
				\Fuel::add_package('facebook');
				
				if(\Facebook\Fb::getUser())
				{
					$me = \Facebook\Fb::api('/me');
					if(!$me){
						throw new \Fuel_Exception('Could not retrieve facebook user info');
					}
					
					if(!$bindto || $bindto instanceof \Users\Model_User){
						$user = \Users\Model_User::find_by_facebook_id($me['id']);
					} else
						$user = false;
					
					if(\Auth::check())
					{
						$uid = \Auth::instance()->get_user_id();
						
						if( !$user ){
							//link user
							$this->_linkfacebook(($bindto ? $bindto:\Users\Model_User::find($uid[1])), $me);
						}
						else
						{
							if($uid[1] != $user->id){						
								\Session::set_flash('error', 'A user already exists with those facebook details. Please logout, login via facebook and unlink your facebook account and try again.');
								\Response::redirect(\Input::get('redirect','%2Flogin'));
							}
						}
					}
					else
					{
						if( !$user ){
							//create & finalise
							$user = \Auth::instance('UnifiedLogin')->create_user($me['email'], md5(rand()), $me['email'],1, array('fname'=>$me['first_name'], 'lname'=>$me['last_name']));
							$user = \Users\Model_User::find($user);
							$this->_linkfacebook($user,$me);
							\Auth::instance('UnifiedLogin')->forced_login($user);
						}else{
							//login found user			
							\Auth::instance('UnifiedLogin')->forced_login($user);
						}
					}
				}
				else
				{
					throw new \Fuel_Exception('There was a problem getting the user in the callback.');
				}
				break;
			case 'twitter':
				\Fuel::add_package('twitter');
				$tokens = \Twitter\Tweet::instance()->get_tokens();
				$twitter_user = \Twitter\Tweet::instance()->call('get', 'account/verify_credentials');
				
				if(!$bindto || $bindto instanceof \Users\Model_User){
					$user = \Users\Model_User::find_by_twitter_id($twitter_user->id);
				} else
					$user = false;
				
				if(\Auth::check())
				{
					$uid = \Auth::instance()->get_user_id();
					
					if( !$user ){
						//link user
						$this->_linktwitter(($bindto ? $bindto:\Users\Model_User::find($uid[1])), array(
							"name"=>$twitter_user->name,
							"id" =>	$twitter_user->id,
							"screen_name" => $twitter_user->screen_name));
					}
					else
					{
						if($uid[1] != $user->id){						
							\Session::set_flash('error', 'A user already exists with those twitter details. Please logout, login via facebook and unlink your facebook account and try again.');
							\Response::redirect(\Input::get('redirect','%2Flogin'));
						}
					}
				}
				else
				{
					if ( ! $user)
					{
						\Session::set('twitter_user_finalise',  array(
							"name"=>$twitter_user->name,
							"id" =>	$twitter_user->id,
							"screen_name" => $twitter_user->screen_name));
						\Response::redirect($finaliseUri);
					}else{
						//login found user			
						$this->forced_login($user);
					}
				}
				break;
			case 'google':
				break;
			case 'openid':
				break;
			case 'auth':
				return parent::login($username, $password);
				break;	
		}	
	}
	
	public function finalise($type, $email)
	{
		switch(strtolower($type)){
			case 'facebook':
				break;
			case 'twitter':
				\Fuel::add_package('twitter');
				$twtr = \Session::get('twitter_user_finalise');
				\Session::delete('twitter_user_finalise');
			
				$name = explode(' ',$twtr['name']);
				$fname = $name[0] ? $name[0] : '';
				$lname = $name[sizeof($name)-1] ? $name[sizeof($name)-1] : '';
				$user = \Auth::instance()->create_user($email, md5(rand()), $email,1, array('fname'=>$fname, 'lname'=>$lname));
			
				$user = \Users\Model_User::find($user);
			
				$this->_linktwitter($user,$twtr);
			
				$this->forced_login($user);
				break;
			case 'google':
				break;
			case 'openid':
				break;
			case 'auth':
				return parent::login($username, $password);
				break;	
		}		
	}
	
	public function _linktwitter($user, $twtr){
	
		$tokens = \Twitter\Tweet::instance()->get_tokens();
		
		$user->twitter_id = $twtr['id'];
		$user->twitter_token = $tokens['oauth_token'];
		$user->twitter_token_secret = $tokens['oauth_token_secret'];
		$user->twitter_screen_name = $twtr['screen_name'];
		$user->save();
		
	}
	public function _linkfacebook($user, $me){
	
		$tokens = \Facebook\Fb::getAccessToken();
		
		$user->facebook_id = $me['id'];
		$user->facebook_screen_name = $me['name'];
		$user->facebook_token = $tokens;
		$user->save();
		
	}
	public function unlink($type, $removeFrom = null){
		if(!$removeFrom)
		{
			$removeFrom = $this->user;
		}
		switch($type){
			case 'facebook':
				$removeFrom->facebook_token = null;
				$removeFrom->facebook_id = null;
				$removeFrom->facebook_screen_name = null;
				$removeFrom->facebook_token_secret = null;
				if($removeFrom instanceof \Pages\Model_Site){
					$removeFrom->facebook_page_id = null;
					$removeFrom->facebook_page_token = null;
					$removeFrom->facebook_page_screen_name = null;
				}
				$removeFrom->save();
				break;
			case 'twitter':
				$removeFrom->twitter_id = null;
				$removeFrom->twitter_token = null;
				$removeFrom->twitter_token_secret = null;
				$removeFrom->twitter_screen_name = null;
				$removeFrom->save();
				break;
			default:
				return false;
		}
		return true;
	}
	public function forced_login($user){
		if(! $user )
			throw new \Fuel_Exception('User must be supplied to force login');
		$this->user = $user;
		\Session::set('username', $user->username);
		\Session::set('login_hash', $this->create_login_hash());
	}
	
	public function logout($redirect = null)
	{
		parent::logout();
		!is_null($redirect) && \Response::redirect($redirect);
	}
	
	public function get_user(){
		return $this->user;
	}
	public function get_twitter_id(){
		if (empty($this->user))
		{
			return false;
		}

		return array($this->id, (int) $this->user['twitter_id']);
	}
	public function get_facebook_id(){
		print_r($this->user);
		if (empty($this->user))
		{
			return false;
		}

		return array($this->id, (int) $this->user['facebook_id']);
	}

}

// end of file simpleauth.php
