<?php namespace Pornfyre\PhpSdk;

use GuzzleHttp\Exception\RequestException as RequestException;
use GuzzleHttp\Exception\ClientException as ClientException;

class Pornfyre {

    private $options;

    protected $encodingType = PHP_QUERY_RFC1738;

    protected $scopes = ['basic'];

    protected $scopeSeparator = ',';

    protected $stateless = false;

	function __construct($config = array()) {
        if(!isset($config['app_id']) || !isset($config['app_secret']) || !isset($config['redirect_uri']) ){
            throw new Exception('Please provide $config array with app_id, app_secret, redirect_uri');
        }
        $this->options = $config;
	}

	protected function getAuthUrl($state)
    {
        return $this->buildAuthUrlFromBase('http://sharesome.com/oauth/authorize', $state);
    }

    protected function getTokenUrl()
    {
        return 'http://sharesome.com/oauth/token';
    }

    protected function getUserByToken($token)
    {
        $response = $this->getHttpClient()->get('http://sharesome.com/api/v1/user', [
            'headers' => [
                'Authorization' => 'Bearer '.$token,
            ],
        ]);

        return json_decode($response->getBody(), true);
    }

    protected function mapUserToObject(array $user)
    {
        return [
            'id'            => $user['user']['id'],
            'username'      => $user['user']['username'],
            'first_name'    => $user['user']['first_name'],
            'last_name'     => $user['user']['last_name'],
            'star'          => $user['user']['last_name'],
            'avatar'        => $user['user']['avatar']
        ];
    }

	public function redirect()
    {
    	$state = null;

        if ($this->usesState()) {
            if(session_status() !== PHP_SESSION_ACTIVE){
                session_start();
            }
            $state = sha1(time().substr(str_shuffle("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"), 0, 20));
        	$_SESSION['state'] = $state;
        }
        header("Location: ".$this->getAuthUrl($state));
        die();
    }


    protected function buildAuthUrlFromBase($url, $state)
    {
        return $url.'?'.http_build_query($this->getCodeFields($state), '', '&', $this->encodingType);
    }

    protected function getCodeFields($state = null)
    {
        $fields = [
            'client_id' => $this->options['app_id'], 'redirect_uri' => $this->options['redirect_uri'],
            'scope' => $this->formatScopes($this->scopes, $this->scopeSeparator),
            'response_type' => 'code',
        ];

        if ($this->usesState()) {
            $fields['state'] = $state;
        }

        return $fields;
    }

    protected function formatScopes(array $scopes, $scopeSeparator)
    {
        return implode($scopeSeparator, $scopes);
    }

    public function user()
    {
        if ($this->hasInvalidState()) {
            throw new Exception;
        }
        $user = $this->mapUserToObject($this->getUserByToken(
            $token = $this->getAccessToken($this->getCode())
        ));
        $user['token'] = $token;
        return $user;
    }

    protected function hasInvalidState()
    {
        if ($this->isStateless()) {
            return false;
        }
        if(session_status() !== PHP_SESSION_ACTIVE){
            session_start();
        }
        return ! ($_GET['state'] === $_SESSION['state']);
    }

    public function getAccessToken($code)
    {
   		try {
   			$response = $this->getHttpClient()->post($this->getTokenUrl(), [
	            'headers' => ['Accept' => 'application/json'],
	            'body' => $this->getTokenFields($code),
	        ]);

	        return $this->parseAccessToken($response->getBody());

		} catch (ClientException $e) {
		    var_dump($e);
		}
    }

    protected function getTokenFields($code)
    {
        return [
            'client_id' => $this->options['app_id'],
            'client_secret' => $this->options['app_secret'],
            'code' => $code,
            'redirect_uri' => $this->options['redirect_uri'],
            'grant_type' => 'authorization_code'
        ];
    }

    protected function parseAccessToken($body)
    {
        return json_decode($body, true)['access_token'];
    }

    protected function getCode()
    {
        return $_GET['code'];
    }

    public function scopes(array $scopes)
    {
        $this->scopes = $scopes;
        return $this;
    }

    protected function getHttpClient()
    {
        return new \GuzzleHttp\Client;
    }

    public function setRequest(Request $request)
    {
        $this->request = $request;
        return $this;
    }

    protected function usesState()
    {
        return ! $this->stateless;
    }

    protected function isStateless()
    {
        return $this->stateless;
    }

    public function stateless()
    {
        $this->stateless = true;
        return $this;
    }
}
