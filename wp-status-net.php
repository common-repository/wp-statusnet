<?php
/*
Plugin Name: WP Status.net
Plugin URI: http://www.xaviermedia.com/wordpress/plugins/wp-status-net.php
Description: Posts your blog posts to one or multiple Status.net servers
Author: Xavier Media
Version: 1.4.2
Author URI: http://www.xaviermedia.com/
*/

add_action('publish_post', 'wpstatusnet_poststatus');
add_action('comment_form', 'wpstatusnet_commentform', 5, 0);

class EpiOAuth
{
  public $version = '1.0';

  protected $requestTokenUrl;
  protected $accessTokenUrl;
  protected $authorizeUrl;
  protected $consumerKey;
  protected $consumerSecret;
  protected $token;
  protected $tokenSecret;
  protected $signatureMethod;

  public function getAccessToken()
  {
    $resp = $this->httpRequest('GET', $this->accessTokenUrl);
    return new EpiOAuthResponse($resp);
  }

  public function getAuthorizationUrl()
  { 
    $retval = "{$this->authorizeUrl}?";

    $token = $this->getRequestToken();
    return $this->authorizeUrl . '?oauth_token=' . $token->oauth_token;
  }

  public function getRequestToken()
  {
    $resp = $this->httpRequest('GET', $this->requestTokenUrl);
    return new EpiOAuthResponse($resp);
  }

  public function httpRequest($method = null, $url = null, $params = null)
  {
    if(empty($method) || empty($url))
      return false;

    if(empty($params['oauth_signature']))
      $params = $this->prepareParameters($method, $url, $params);

    switch($method)
    {
      case 'GET':
        return $this->httpGet($url, $params);
        break;
      case 'POST':
        return $this->httpPost($url, $params);
        break;
    }
  }

  public function setToken($token = null, $secret = null)
  {
    $params = func_get_args();
    $this->token = $token;
    $this->tokenSecret = $secret;
  } 

  public function encode($string)
  {
    return rawurlencode(utf8_encode($string));
  }

  protected function addOAuthHeaders(&$ch, $url, $oauthHeaders)
  {
    $_h = array('Expect:');
    $urlParts = parse_url($url);
    $oauth = 'Authorization: OAuth realm="' . $urlParts['path'] . '",';
    foreach($oauthHeaders as $name => $value)
    {
      $oauth .= "{$name}=\"{$value}\",";
    }
    $_h[] = substr($oauth, 0, -1);
  
    curl_setopt($ch, CURLOPT_HTTPHEADER, $_h); 
  }

  protected function generateNonce()
  {
    if(isset($this->nonce)) // for unit testing
      return $this->nonce;

    return md5(uniqid(rand(), true));
  }

  protected function generateSignature($method = null, $url = null, $params = null)
  {
    if(empty($method) || empty($url))
      return false;


    // concatenating
    $concatenatedParams = '';
    foreach($params as $k => $v)
    {
      $v = $this->encode($v);
      $concatenatedParams .= "{$k}={$v}&";
    }
    $concatenatedParams = $this->encode(substr($concatenatedParams, 0, -1));

    // normalize url
    $normalizedUrl = $this->encode($this->normalizeUrl($url));
    $method = $this->encode($method); // don't need this but why not?

    $signatureBaseString = "{$method}&{$normalizedUrl}&{$concatenatedParams}";
    return $this->signString($signatureBaseString);
  }

  protected function httpGet($url, $params = null)
  {
    if(count($params['request']) > 0)
    {
      $url .= '?';
      foreach($params['request'] as $k => $v)
      {
        $url .= "{$k}={$v}&";
      }
      $url = substr($url, 0, -1);
    }
    $ch = curl_init($url);
    $this->addOAuthHeaders($ch, $url, $params['oauth']);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $resp  = $this->curl->addCurl($ch);

    return $resp;
  }

  protected function httpPost($url, $params = null)
  {
    $ch = curl_init($url);
    $this->addOAuthHeaders($ch, $url, $params['oauth']);
    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($params['request']));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $resp  = $this->curl->addCurl($ch);
    return $resp;
  }

  protected function normalizeUrl($url = null)
  {
    $urlParts = parse_url($url);
    $scheme = strtolower($urlParts['scheme']);
    $host   = strtolower($urlParts['host']);
    $port = intval($urlParts['port']);

    $retval = "{$scheme}://{$host}";
    if($port > 0 && ($scheme === 'http' && $port !== 80) || ($scheme === 'https' && $port !== 443))
    {
      $retval .= ":{$port}";
    }
    $retval .= $urlParts['path'];
    if(!empty($urlParts['query']))
    {
      $retval .= "?{$urlParts['query']}";
    }

    return $retval;
  }

  protected function prepareParameters($method = null, $url = null, $params = null)
  {
    if(empty($method) || empty($url))
      return false;

    $oauth['oauth_consumer_key'] = $this->consumerKey;
    $oauth['oauth_token'] = $this->token;
    $oauth['oauth_nonce'] = $this->generateNonce();
    $oauth['oauth_timestamp'] = !isset($this->timestamp) ? time() : $this->timestamp; // for unit test
    $oauth['oauth_signature_method'] = $this->signatureMethod;
    $oauth['oauth_version'] = $this->version;

    // encoding
    array_walk($oauth, array($this, 'encode'));
    if(is_array($params))
      array_walk($params, array($this, 'encode'));
    $encodedParams = array_merge($oauth, (array)$params);

    // sorting
    ksort($encodedParams);

    // signing
    $oauth['oauth_signature'] = $this->encode($this->generateSignature($method, $url, $encodedParams));
    return array('request' => $params, 'oauth' => $oauth);
  }

  protected function signString($string = null)
  {
    $retval = false;
    switch($this->signatureMethod)
    {
      case 'HMAC-SHA1':
        $key = $this->encode($this->consumerSecret) . '&' . $this->encode($this->tokenSecret);
        $retval = base64_encode(hash_hmac('sha1', $string, $key, true));
        break;
    }

    return $retval;
  }

  public function __construct($consumerKey, $consumerSecret, $signatureMethod='HMAC-SHA1')
  {
    $this->consumerKey = $consumerKey;
    $this->consumerSecret = $consumerSecret;
    $this->signatureMethod = $signatureMethod;
    $this->curl = EpiCurl::getInstance();
  }
}

class EpiOAuthResponse
{
  private $__resp;

  public function __construct($resp)
  {
    $this->__resp = $resp;
  }

  public function __get($name)
  {
    if($this->__resp->code < 200 || $this->__resp->code > 299)
      return false;

    parse_str($this->__resp->data, $result);
    foreach($result as $k => $v)
    {
      $this->$k = $v;
    }

    return $result[$name];
  }
}

class EpiCurl
{
  const timeout = 3;
  static $inst = null;
  static $singleton = 0;
  private $mc;
  private $msgs;
  private $running;
  private $requests = array();
  private $responses = array();
  private $properties = array();

  function __construct()
  {
    if(self::$singleton == 0)
    {
      throw new Exception('This class cannot be instantiated by the new keyword.  You must instantiate it using: $obj = EpiCurl::getInstance();');
    }

    $this->mc = curl_multi_init();
    $this->properties = array(
      'code'  => CURLINFO_HTTP_CODE,
      'time'  => CURLINFO_TOTAL_TIME,
      'length'=> CURLINFO_CONTENT_LENGTH_DOWNLOAD,
      'type'  => CURLINFO_CONTENT_TYPE
      );
  }

  public function addCurl($ch)
  {
    $key = (string)$ch;
    $this->requests[$key] = $ch;

    $res = curl_multi_add_handle($this->mc, $ch);
    
    // (1)
    if($res === CURLM_OK || $res === CURLM_CALL_MULTI_PERFORM)
    {
      do {
          $mrc = curl_multi_exec($this->mc, $active);
      } while ($mrc === CURLM_CALL_MULTI_PERFORM);

      return new EpiCurlManager($key);
    }
    else
    {
      return $res;
    }
  }

  public function getResult($key = null)
  {
    if($key != null)
    {
      if(isset($this->responses[$key]))
      {
        return $this->responses[$key];
      }

      $running = null;
      do
      {
        $resp = curl_multi_exec($this->mc, $runningCurrent);
        if($running !== null && $runningCurrent != $running)
        {
          $this->storeResponses($key);
          if(isset($this->responses[$key]))
          {
            return $this->responses[$key];
          }
        }
        $running = $runningCurrent;
      }while($runningCurrent > 0);
    }

    return false;
  }

  private function storeResponses()
  {
    while($done = curl_multi_info_read($this->mc))
    {
      $key = (string)$done['handle'];
      $this->responses[$key]['data'] = curl_multi_getcontent($done['handle']);
      foreach($this->properties as $name => $const)
      {
        $this->responses[$key][$name] = curl_getinfo($done['handle'], $const);
        curl_multi_remove_handle($this->mc, $done['handle']);
      }
    }
  }

  static function getInstance()
  {
    if(self::$inst == null)
    {
      self::$singleton = 1;
      self::$inst = new EpiCurl();
    }

    return self::$inst;
  }
}

class EpiCurlManager
{
  private $key;
  private $epiCurl;

  function __construct($key)
  {
    $this->key = $key;
    $this->epiCurl = EpiCurl::getInstance();
  }

  function __get($name)
  {
    $responses = $this->epiCurl->getResult($this->key);
    return $responses[$name];
  }
}

/*
 * Credits:
 *  - (1) Alistair pointed out that curl_multi_add_handle can return CURLM_CALL_MULTI_PERFORM on success.
 */

class EpiTwitter extends EpiOAuth
{
  const EPITWITTER_SIGNATURE_METHOD = 'HMAC-SHA1';
  protected $requestTokenUrl = 'http://twitter.com/oauth/request_token';
  protected $accessTokenUrl = 'http://twitter.com/oauth/access_token';
  protected $authorizeUrl = 'http://twitter.com/oauth/authorize';
  protected $apiUrl = 'http://twitter.com';

  public function __call($name, $params = null)
  {
    $parts  = explode('_', $name);
    $method = strtoupper(array_shift($parts));
    $parts  = implode('_', $parts);
    $url    = $this->apiUrl . '/' . preg_replace('/[A-Z]|[0-9]+/e', "'/'.strtolower('\\0')", $parts) . '.json';
    if(!empty($params))
      $args = array_shift($params);

    return new EpiTwitterJson(call_user_func(array($this, 'httpRequest'), $method, $url, $args));
  }

  public function __construct($consumerKey = null, $consumerSecret = null, $oauthToken = null, $oauthTokenSecret = null, $oauthServer = "twitter.com")
  {
	  $requestTokenUrl = 'http://'. $oauthServer .'/oauth/request_token';
	  $accessTokenUrl = 'http://'. $oauthServer .'/oauth/access_token';
	  $authorizeUrl = 'http://'. $oauthServer .'/oauth/authorize';
	  $apiUrl = 'http://'. $oauthServer .'';

    parent::__construct($consumerKey, $consumerSecret, self::EPITWITTER_SIGNATURE_METHOD);
    $this->setToken($oauthToken, $oauthTokenSecret);
  }
}

class EpiTwitterJson
{
  private $resp;

  public function __construct($resp)
  {
    $this->resp = $resp;
  }

  public function __get($name)
  {
    $this->responseText = $this->resp->data;
    $this->response = (array)json_decode($this->responseText, 1);
    foreach($this->response as $k => $v)
    {
      $this->$k = $v;
    }

    return $this->$name;
  }
}

class CurlRequest2
{
    private $ch;
    /**
     * Init curl session
     *
     * $params = array('url' => '',
     *                    'host' => '',
     *                   'header' => '',
     *                   'method' => '',
     *                   'referer' => '',
     *                   'cookie' => '',
     *                   'post_fields' => '',
     *                    ['login' => '',]
     *                    ['password' => '',]     
     *                   'timeout' => 0
     *                   );
     */               
    public function init($params)
    {
        $this->ch = curl_init();
        $user_agent = 'Mozilla/5.0 (Windows; U;Windows NT 5.1; ru; rv:1.8.0.9) Gecko/20061206 Firefox/1.5.0.9';
        $header = array(
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5",
        "Accept-Language: ru-ru,ru;q=0.7,en-us;q=0.5,en;q=0.3",
        "Accept-Charset: windows-1251,utf-8;q=0.7,*;q=0.7",
        "Keep-Alive: 300");
        if (isset($params['host']) && $params['host'])      $header[]="Host: ".$host;
        if (isset($params['header']) && $params['header']) $header[]=$params['header'];
       
        @curl_setopt ( $this -> ch , CURLOPT_RETURNTRANSFER , 1 );
        @curl_setopt ( $this -> ch , CURLOPT_VERBOSE , 1 );
        @curl_setopt ( $this -> ch , CURLOPT_HEADER , 1 );
       
        if ($params['method'] == "HEAD") @curl_setopt($this -> ch,CURLOPT_NOBODY,1);
        @curl_setopt ( $this -> ch, CURLOPT_FOLLOWLOCATION, 1);
        @curl_setopt ( $this -> ch , CURLOPT_HTTPHEADER, $header );
        if ($params['referer'])    @curl_setopt ($this -> ch , CURLOPT_REFERER, $params['referer'] );
        @curl_setopt ( $this -> ch , CURLOPT_USERAGENT, $user_agent);
        if ($params['cookie'])    @curl_setopt ($this -> ch , CURLOPT_COOKIE, $params['cookie']);

        if ( $params['method'] == "POST" )
        {
            curl_setopt( $this -> ch, CURLOPT_POST, true );
            curl_setopt( $this -> ch, CURLOPT_POSTFIELDS, $params['post_fields'] );
        }
        @curl_setopt( $this -> ch, CURLOPT_URL, $params['url']);
        @curl_setopt ( $this -> ch , CURLOPT_SSL_VERIFYPEER, 0 );
        @curl_setopt ( $this -> ch , CURLOPT_SSL_VERIFYHOST, 0 );
        if (isset($params['login']) & isset($params['password']))
            @curl_setopt($this -> ch , CURLOPT_USERPWD,$params['login'].':'.$params['password']);
        @curl_setopt ( $this -> ch , CURLOPT_TIMEOUT, $params['timeout']);
    }
   
    /**
     * Make curl request
     *
     * @return array  'header','body','curl_error','http_code','last_url'
     */
    public function exec()
    {
        $response = curl_exec($this->ch);
        $error = curl_error($this->ch);
        $result = array( 'header' => '',
                         'body' => '',
                         'curl_error' => '',
                         'http_code' => '',
                         'last_url' => '');
        if ( $error != "" )
        {
            $result['curl_error'] = $error;
            return $result;
        }
       
        $header_size = curl_getinfo($this->ch,CURLINFO_HEADER_SIZE);
        $result['header'] = substr($response, 0, $header_size);
        $result['body'] = substr( $response, $header_size );
        $result['http_code'] = curl_getinfo($this -> ch,CURLINFO_HTTP_CODE);
        $result['last_url'] = curl_getinfo($this -> ch,CURLINFO_EFFECTIVE_URL);
        return $result;
    }
}

function wpstatusnet_poststatus($post_id)
{

	$status_net = get_post_meta($post_id, 'status_net', true);
	if (!($status_net == 'yes')) {
		query_posts('p=' . $post_id);

		if (have_posts()) 
		{
			$opt  = get_option('wpstatusnetoptions');
			$options = unserialize($opt);

			the_post();

			$link = get_permalink();
	
			if ($options[apitype] == "yourls.org")
			{
				$jsonstring = file_get_contents('http://'. $options[apiid] .'/yourls-api.php?signature='. $options[apikey] .'&action=shorturl&format=json&url='. urlencode($link));

				$json = json_decode($jsonstring,true);

				if ($json[status] == "success")
				{
					$link = $json[shorturl];
				}
			}
			else if ($options[apitype] == "is.gd")
			{
				$link = file_get_contents('http://is.gd/api.php?longurl='. urlencode($link));
			}
			else if ($options[apitype] == "metamark.net")
			{
				$link = file_get_contents('http://metamark.net/api/rest/simple?long_url='. urlencode($link));
			}
			else if ($options[apitype] == "mrte.ch")
			{
				$jsonstring = file_get_contents('http://api.mrte.ch/go.php?action=shorturl&format=json&url='. urlencode($link));
	
				$json = json_decode($jsonstring,true);

				if ($json[statusCode] == "200")
				{
					$link = $json[shorturl];
				}
			}
			else if ($options[apitype] == "tinyurl.com")
			{
				$link = file_get_contents('http://tinyurl.com/api-create.php?url=' . $link);
			}
			else if ($options[apitype] == "2ve.org")
			{
				$jsonstring = file_get_contents('http://api.2ve.org/api.php?action=makeshorter&fileformat=json&longlink='. urlencode($link) .'&api='. $options[apiid] .'&key='. $options[apikey]);
	
				$json = json_decode($jsonstring,true);

				if ($json[responsecode] == "200")
				{
					$link = $json[shortlink];
				}
			}
			else if ($options[apitype] == "bit.ly")
			{
				$jsonstring = file_get_contents('http://api.bit.ly/shorten?version=2.0.1&longUrl='. urlencode($link) .'&login='. $options[apiid] .'&apiKey='. $options[apikey]);

				$json = json_decode($jsonstring,true);

				if ($json[statusCode] == "OK")
				{
					$link = $json[results][$link][shortUrl];
				}
			}

			$title = get_the_title();

	     
			$posting = new CurlRequest2();
	
			$num = count($options[statusserver]);
			for ($i = 0; $i < $num; $i++)
			{
				if ($options[statususer][$i] != "")
				{

					if ($options[statusprefix][$i] == "")
					{
						$statuspost = '';
					}
					else
					{
						$statuspost = $options[statusprefix][$i] .' ';
					}


					if ($title > (134 - strlen($link) - strlen($options[statusprefix][$i])))
					{
					    $statuspost .= $options[statusprefix][$i] .' '. substr($title,0,(134 - strlen($link) - strlen($options[statusprefix][$i]))) .'... - '. $link;
					}
					else
					{
					    $statuspost .= $title .' - '. $link;
					}

					if ($options[statussuffix][$i] == "")
					{
						$statuspost .= '';
					}
					else
					{
						$statuspost .= ' '. $options[statussuffix][$i];
					}

					if ($options[statusauthtype][$i] == "oauth")
					{

						if ($options[statuspath][$i] == "" || $options[statustype][$i] == "twitter")
						{
							$oauthServer = $options[statusserver][$i];
						}
						else
						{
							$oauthServer = $options[statusserver][$i] ."/". $options[statuspath][$i];
						}

						$OauthObj = new EpiTwitter($options[statususer][$i], $options[statususer2][$i],$options[statuspwd][$i],$options[statuspwd2][$i],$oauthServer);

						$OauthInfo= $OauthObj->get_accountVerify_credentials();
						$OauthInfo->response;

						$OauthInfo= $OauthObj->post_statusesUpdate(array('status' => $statuspost));
						$statusid =  $OauthInfo->response['id'];

					}
					else
					{
						if ($options[statuspath][$i] == "")
						{
							$server = "http://". $options[statusserver][$i] ."/statuses/update.json";
						}
						else
						{
							$server = "http://". $options[statusserver][$i] ."/". $options[statuspath][$i] ."/statuses/update.json";
						}
	
						$params = array('url' => $server,
							'host' => '',
							'header' => '',
							'method' => 'POST', // 'POST','HEAD'
							'referer' => '',
							'cookie' => '',
						      'post_fields' => 'status='. urlencode($statuspost) .'&source=WP-status-net',
						      'login' => $options[statususer][$i],
						      'password' => $options[statuspwd][$i],     
							'timeout' => 20
							);

	//					add_post_meta($post_id, $options[statusserver][$i], serialize($params));
	
	
						$posting->init($params);

						$postingstatus = $posting->exec();
					}

				}
			}


			add_post_meta($post_id, 'status_net', 'yes');
		}
	}
}

function wpstatusnet_commentform()
{
	$opt  = get_option('wpstatusnetoptions');
	$options = unserialize($opt);
	if ($options[pluginlink] == "poweredby")
	{
		echo '<p>Powered by <a href="http://www.xaviermedia.com/wordpress/plugins/wp-status-net.php">WP Status.net plugin</A>.</p>';
	}
}

function wpstatusnet_test()
{
	echo 'Test';

}

function wpstatusnet_options()
{

      	if ( 'save' == $_REQUEST['action'] ) 
		{
			$options = array(
				"apitype" => $_REQUEST[apitype],
				"apiid" => $_REQUEST[apiid],
				"apikey" => $_REQUEST[apikey],
				"pluginlink" => $_REQUEST[pluginlink],
				"statustype" => array(),
				"statusauthtype" => array(),
				"statusservers" => array(),
				"statuspath" => array(),
				"statususer" => array(),
				"statuspwd" => array(),
				"statusprefix" => array(),
				"statussuffix" => array()
				);

			$statustype = $_REQUEST[statustype];
			$statusauthtype = $_REQUEST[statusauthtype];
			$statusserver = $_REQUEST[statusserver];
			$statuspath = $_REQUEST[statuspath];
			$statususer = $_REQUEST[statususer];
			$statuspwd = $_REQUEST[statuspwd];
			$statususer2 = $_REQUEST[statususer2];
			$statuspwd2 = $_REQUEST[statuspwd2];
			$statusprefix = $_REQUEST[statusprefix];
			$statussuffix = $_REQUEST[statussuffix];

			$num = count($statusserver);
			for ($i = 0; $i < $num; $i++)
			{
				if ($statususer[$i] != "")
				{

					if ($statustype[$i] == "twitter")
					{
						$statusserver[$i] = "twitter.com";
						$statuspath[$i] = "";
						$statusauthtype[$i] = "oauth";
					}

					$statusserver[$i] = str_replace("http://","",$statusserver[$i]);
					if (substr($statusserver[$i],-1,1) == "/")
					{
						$statusserver[$i] = substr($statusserver[$i],0,-1);
					}
					if (substr($statuspath[$i],-1,1) == "/")
					{
						$statuspath[$i] = substr($statuspath[$i],0,-1);
					}
					if (substr($statuspath[$i],0,1) == "/")
					{
						$statuspath[$i] = substr($statuspath[$i],1);
					}

//					if ($statusserver[$i] == "myxavier.com" && $options[pluginlink] == "")
//					{
//						$options[pluginlink] = "poweredby";
//					}

					$options[statustype][] = $statustype[$i];
					$options[statusauthtype][] = $statusauthtype[$i];
					$options[statusserver][] = $statusserver[$i];
					$options[statuspath][] = $statuspath[$i];
					$options[statususer][] = $statususer[$i];
					$options[statuspwd][] = $statuspwd[$i];
					$options[statususer2][] = $statususer2[$i];
					$options[statuspwd2][] = $statuspwd2[$i];
					$options[statusprefix][] = $statusprefix[$i];
					$options[statussuffix][] = $statussuffix[$i];
				}
			}

			$opt = serialize($options);
			update_option('wpstatusnetoptions', $opt);
	}
	else
	{
		$opt  = get_option('wpstatusnetoptions');
		$options = unserialize($opt);
	}
	?>
	<STYLE>
	.hiddenfield 
	{
		display:none;
	}
	.nothiddenfield 
	{
	}
	</STYLE>

	<div class="updated fade-ff0000"><p><strong>Need web hosting for your blog?</strong> Get 10 Gb web space and unlimited bandwidth for only $3.40/month at <a href="http://2ve.org/xMY3/" target="_blank">eXavier.com</a>, or get the Ultimate Plan with unlimited space and bandwidth for only $14.99/month.</p></div>


	<form action="<?php echo $_SERVER['REQUEST_URI'] ?>" method="post" name=pf>
	<input type="hidden" name="action" value="save" />
	<h1>WP Status.net Options</h1>
	If you get stuck on any of these options, please have a look at the <a href="http://www.xaviermedia.com/wordpress/plugins/wp-status-net.php">WP Status.net plugin page</a> or visit the <a href="http://www.xavierforum.com/php-&-cgi-scripts-f3.html">support forum</a>.
	<h2>Link Shortener</h2>
	<p>Select the link shortener you would like to use.</p>
	<p>
	<INPUT TYPE=radio NAME=apitype VALUE="" <?php	if ($options[apitype] == "") { echo ' CHECKED'; } ?> onClick="javascript:document.getElementById('apikeys').className = 'hiddenfield';"> <B>Don't</B> use any service to get short links<BR />

	<INPUT TYPE=radio NAME=apitype VALUE="yourls.org" <?php	if ($options[apitype] == "yourls.org") { echo ' CHECKED'; } ?> onClick="javascript:alert('To use this service you need to read the instructions below!');document.getElementById('apikeys').className = 'nothiddenfield';document.getElementById('yourlssetup').className = 'nothiddenfield';"> <A HREF="http://yourls.org/" TARGET="_blank">Yourls.org on your own domain</A> *<BR />

	<INPUT TYPE=radio NAME=apitype VALUE="is.gd" <?php	if ($options[apitype] == "is.gd") { echo ' CHECKED'; } ?> onClick="javascript:document.getElementById('apikeys').className = 'hiddenfield';"> <A HREF="http://is.gd/" TARGET="_blank">is.gd</A><BR />

	<INPUT TYPE=radio NAME=apitype VALUE="metamark.net" <?php	if ($options[apitype] == "metamark.net") { echo ' CHECKED'; } ?> onClick="javascript:document.getElementById('apikeys').className = 'hiddenfield';"> <A HREF="http://metamark.net/" TARGET="_blank">metamark.net</A><BR />

	<INPUT TYPE=radio NAME=apitype VALUE="mrte.ch" <?php	if ($options[apitype] == "mrte.ch") { echo ' CHECKED'; } ?> onClick="javascript:document.getElementById('apikeys').className = 'hiddenfield';"> <A HREF="http://mrte.ch/" TARGET="_blank">mrte.ch</A><BR />

	<INPUT TYPE=radio NAME=apitype VALUE="tinyurl.com" <?php	if ($options[apitype] == "tinyurl.com") { echo ' CHECKED'; } ?> onClick="javascript:document.getElementById('apikeys').className = 'hiddenfield';"> <A HREF="http://tinyurl.com/" TARGET="_blank">tinyurl.com</A><BR />

	<INPUT TYPE=radio NAME=apitype VALUE="2ve.org" <?php	if ($options[apitype] == "2ve.org") { echo ' CHECKED'; } ?> onClick="javascript:alert('Don\'t forget to fill in the API ID and API key fields below for this link shortener');document.getElementById('apikeys').className = 'nothiddenfield';"> <A HREF="http://2ve.org/" TARGET="_blank">2ve.org</A> <B>*</B><BR />

	<INPUT TYPE=radio NAME=apitype VALUE="bit.ly" <?php	if ($options[apitype] == "bit.ly") { echo ' CHECKED'; } ?> onClick="javascript:alert('Don\'t forget to fill in the API ID and API key fields below for this link shortener');document.getElementById('apikeys').className = 'nothiddenfield';"> <A HREF="http://bit.ly/" TARGET="_blank">bit.ly</A> <B>*</B><BR />

	<BR /><B>*</B> = This link shortener service require an <B>API ID</B> and/or an <B>API Key</B> to work. Please see the documentation at the link shorteners web site.

	<DIV id=yourlssetup class=<?php if($options[apitype] == "yourls.org") { echo 'nothiddenfield'; } else { echo 'hiddenfield'; } ?>>
	<H3>Yourls.org Setup Instructions:</H3>
	To be able to use the Yourls.org option below on your own domain name you need to follow these instructions. If you're a newbie this option is not really for you.
	<OL>
	<LI> Download Yourls.org from <A HREF="http://www.yourls.org/" TARGET="_blank">www.yourls.org</A> and follow the setup instructions to install Yourls.org on your own domain name
	<LI> Select the Yourls.org option above
	<LI> Fill in your <B>API key</B>/signature in the <B>API key</B> field below. THe password and user name option will not work so you have to <a HREF="http://yourls.org/passwordlessapi" TARGET="_blank">setup Yourls.org to work with signatures</A>.
	<LI> Fill in the <B>domain name</B> on which you've installed Yourls.org on in the API ID field. Do not include any http:// nor any / at the end of the domain name!<BR/>
		For example if the Yourls.org script is installed at <i>http://www.sampleaddress.com/yourls-api.php</i>, then you <U>only</U> fill in <i>sampleaddress.com</i> in the API ID field.
	</OL>
	</DIV>	

	<div id=apikeys class=<?php if($options[apitype] == "2ve.org" || $options[apitype] == "bit.ly" || $options[apitype] == "yourls.org") { echo 'nothiddenfield'; } else { echo 'hiddenfield'; } ?>>
	<h3>Link Shortener API ID and API Key:</h3>
	Depending on what you selected above, some link shorteners require that you sign up at their web site to get an API ID (or API login) and/or an API key. For more information on what's required to use the link shortener you've selected, please see the documentation at the web site of the link shortener.<BR />
	API ID: &nbsp; <INPUT TYPE=text NAME=apiid VALUE="<?php echo $options[apiid]; ?>" SIZE=40> (this may sometimes be called "login", and in the case of Yourls.org it's the domain name where you installed Yourls.org)<BR />		
	API Key: <INPUT TYPE=text NAME=apikey VALUE="<?php echo $options[apikey]; ?>" SIZE=40> (if just a key is required, leave the ID field blank)<BR />	
	</div>	

	<h2>Link to Xavier Media&reg;</h2>

	<P>To support our work, please add a link to us in your blog. </P>

	<P><INPUT TYPE=checkbox VALUE="poweredby" NAME=pluginlink <?php if ($options[pluginlink] == "poweredby") { echo ' CHECKED'; } ?>> "Powered by WP-Status.net plugin"</P>

	<h2>Status.net servers and user accounts</h2>

	<p>Fill in the Status.net servers you would like to post status updates to. To post to for example <A HREF="http://identi.ca/" TARGET="_blank">identi.ca</A> just fill in <B>identi.ca</B> as server, <B>api</B> as path and your user name and password.</p>
	<p>To turn off updates to a server, just remove the user name for that server and update options.</p>
	<p>Post prefix and post suffix are optional, but if you would like to post some text or perhaps a hash tag before/after all your posts you can specify a unique prefix/suffix for each server/account.</p>

	<p><b>How to use Oauth with Twitter?</b><br />

1. Register a new application at <a href="http://dev.twitter.com/apps/new" target="_blank">dev.twitter.com/apps/new</a><br />
&nbsp; &nbsp; * Application Type must be set to Browser<br />
&nbsp; &nbsp; * The Callback URL should be the URL of your blog<br />
&nbsp; &nbsp; * Default Access type MUST be set to Read & Write<br />
2. Fill in the Consumer Key and Consumer Secret in the correct fields (will show up as soon as you select Server Type "Twitter" and "Oauth" in the server list (user name column))<br />
3. Click on the link called "My Access Tokens" at http://dev.twitter.com (right menu)<br />
4. Fill in your Access Token and the Access Token Secret in the correct fields (password column)<br />
5. Now you should be able to post to Twitter<br /></p>


	<table class="widefat post fixed" cellspacing="0">	
	<thead>
		<tr>
			<th id="server" class="manage-column column-title" style="" scope="col">Type</th>
			<th id="server" class="manage-column column-title" style="" scope="col">Server</th>
			<th id="path" class="manage-column column-title" style="" scope="col">Path</th>
			<th id="user" class="manage-column column-title" style="" scope="col">User Name</th>
			<th id="pwd" class="manage-column column-title" style="" scope="col">Password</th>
			<th id="prefix" class="manage-column column-title" style="" scope="col">Post Prefix</th>
			<th id="suffix" class="manage-column column-title" style="" scope="col">Post Suffix</th>
		</tr>
	</thead>
	<tfoot>
		<tr>
			<th id="server" class="manage-column column-title" style="" scope="col">Type</th>
			<th id="server" class="manage-column column-title" style="" scope="col">Server</th>
			<th id="path" class="manage-column column-title" style="" scope="col">Path</th>
			<th id="user" class="manage-column column-title" style="" scope="col">User Name</th>
			<th id="pwd" class="manage-column column-title" style="" scope="col">Password</th>
			<th id="prefix" class="manage-column column-title" style="" scope="col">Post Prefix</th>
			<th id="suffix" class="manage-column column-title" style="" scope="col">Post Suffix</th>
		</tr>
	</tfoot>	
	<tbody>	
<?php
	$num = count($options[statusserver]) + 5;
	if ($num == 5)
	{
		$options[statustype][0] = "status";
		$options[statusserver][0] = "myxavier.com";
		$options[statuspath][0] = "api";

		$options[statustype][1] = "status";
		$options[statusserver][1] = "identi.ca";
		$options[statuspath][1] = "api";

		$num = 5;
	}
	for ($i = 0; $i < $num; $i++)
	{
	?>
		<tr>
			<th id="type" class="manage-column column-title" style="" scope="col"><SELECT ID=statustype<?php echo $i ?> onChange="javascript:if(document.getElementById('statustype<?php echo $i ?>').options[document.getElementById('statustype<?php echo $i ?>').selectedIndex].value == 'twitter') { document.getElementById('statusserver<?php echo $i ?>').className = 'hiddenfield'; document.getElementById('statuspath<?php echo $i ?>').className = 'hiddenfield'; document.getElementById('statusauthtype<?php echo $i ?>').selectedIndex = 1; } else { document.getElementById('statusauthtype<?php echo $i ?>').selectedIndex = 0; document.getElementById('statusserver<?php echo $i ?>').className = 'nothiddenfield'; document.getElementById('statuspath<?php echo $i ?>').className = 'nothiddenfield'; } if(document.getElementById('statusauthtype<?php echo $i ?>').options[document.getElementById('statusauthtype<?php echo $i ?>').selectedIndex].value == 'oauth') { document.getElementById('oauthA<?php echo $i ?>').className = 'nothiddenfield'; document.getElementById('oauthB<?php echo $i ?>').className = 'nothiddenfield'; document.getElementById('oauthC<?php echo $i ?>').className = 'nothiddenfield'; document.getElementById('oauthD<?php echo $i ?>').className = 'nothiddenfield';} else  { document.getElementById('oauthA<?php echo $i ?>').className = 'hiddenfield'; document.getElementById('oauthB<?php echo $i ?>').className = 'hiddenfield'; document.getElementById('oauthC<?php echo $i ?>').className = 'hiddenfield'; document.getElementById('oauthD<?php echo $i ?>').className = 'hiddenfield'; }" NAME=statustype[<?php echo $i ?>]><OPTION VALUE="status" <?php if($options[statustype][$i] == "status") { echo ' SELECTED'; } ?>">Status.net</OPTION><OPTION VALUE="twitter" <?php if($options[statustype][$i] == "twitter") { echo ' SELECTED'; } ?>">Twitter</OPTION></SELECT>
			<SELECT ID=statusauthtype<?php echo $i ?> NAME=statusauthtype[<?php echo $i ?>] onChange="javascript:if(document.getElementById('statustype<?php echo $i ?>').options[document.getElementById('statustype<?php echo $i ?>').selectedIndex].value == 'twitter') { document.getElementById('statusauthtype<?php echo $i ?>').selectedIndex = 1; } else { document.getElementById('statusauthtype<?php echo $i ?>').selectedIndex = 0; }; if(document.getElementById('statusauthtype<?php echo $i ?>').options[document.getElementById('statusauthtype<?php echo $i ?>').selectedIndex].value == 'oauth') { document.getElementById('oauthA<?php echo $i ?>').className = 'nothiddenfield'; document.getElementById('oauthB<?php echo $i ?>').className = 'nothiddenfield'; document.getElementById('oauthC<?php echo $i ?>').className = 'nothiddenfield'; document.getElementById('oauthD<?php echo $i ?>').className = 'nothiddenfield';} else  { document.getElementById('oauthA<?php echo $i ?>').className = 'hiddenfield'; document.getElementById('oauthB<?php echo $i ?>').className = 'hiddenfield'; document.getElementById('oauthC<?php echo $i ?>').className = 'hiddenfield'; document.getElementById('oauthD<?php echo $i ?>').className = 'hiddenfield'; }"><OPTION VALUE="basic" <?php if($options[statusauthtype][$i] == "basic") { echo ' SELECTED'; } ?>">Basic Auth</OPTION><OPTION VALUE="oauth" <?php if($options[statusauthtype][$i] == "oauth") { echo ' SELECTED'; } ?>">Oauth</OPTION></SELECT>
			</th>
			<th id="server" class="manage-column column-title" style="" scope="col"><INPUT TYPE=text ID=statusserver<?php echo $i ?> <?php if ($options[statustype][$i] == "twitter") { echo 'CLASS=hiddenfield'; } ?> NAME=statusserver[<?php echo $i ?>] VALUE="<?php echo $options[statusserver][$i]; ?>" SIZE=20></th>
			<th id="path" class="manage-column column-title" style="" scope="col"><INPUT TYPE=text ID=statuspath<?php echo $i ?> <?php if ($options[statustype][$i] == "twitter") { echo 'CLASS=hiddenfield'; } ?> NAME=statuspath[<?php echo $i ?>] VALUE="<?php echo $options[statuspath][$i]; ?>" SIZE=20></th>
			<th id="user" class="manage-column column-title" style="" scope="col"><B ID=oauthA<?php echo $i ?> <?php if ($options[statusauthtype][$i] != "oauth") { echo 'CLASS=hiddenfield'; } ?>>Consumer key:</B><INPUT TYPE=text NAME=statususer[<?php echo $i ?>] VALUE="<?php echo $options[statususer][$i]; ?>" SIZE=20><BR /><B ID=oauthC<?php echo $i ?> <?php if ($options[statusauthtype][$i] != "oauth") { echo 'CLASS=hiddenfield'; } ?>>Consumer Secret:<INPUT TYPE=text NAME=statususer2[<?php echo $i ?>] VALUE="<?php echo $options[statususer2][$i]; ?>" SIZE=20></B></th>
			<th id="pwd" class="manage-column column-title" style="" scope="col"><B ID=oauthB<?php echo $i ?> <?php if ($options[statusauthtype][$i] != "oauth") { echo 'CLASS=hiddenfield'; } ?>>Access Token:</B><INPUT TYPE=password NAME=statuspwd[<?php echo $i ?>] VALUE="<?php echo $options[statuspwd][$i]; ?>" SIZE=20><BR /><B ID=oauthD<?php echo $i ?> <?php if ($options[statusauthtype][$i] != "oauth") { echo 'CLASS=hiddenfield'; } ?>>Access Token Secret:<INPUT TYPE=text NAME=statuspwd2[<?php echo $i ?>] VALUE="<?php echo $options[statuspwd2][$i]; ?>" SIZE=20></B></th>
			<th id="prefix" class="manage-column column-title" style="" scope="col"><INPUT TYPE=text NAME=statusprefix[<?php echo $i ?>] VALUE="<?php echo $options[statusprefix][$i]; ?>" SIZE=20></th>
			<th id="suffix" class="manage-column column-title" style="" scope="col"><INPUT TYPE=text NAME=statussuffix[<?php echo $i ?>] VALUE="<?php echo $options[statussuffix][$i]; ?>" SIZE=20></th>
		</tr>
	<?php
	}
?>	</tbody>
	</table>	

	<div class="submit"><input type="submit" name="info_update" value="Update Options" class="button-primary"  /></div></form>
	<a target="_blank" href="http://feed.xaviermedia.com/xm-wordpress-stuff/"><img src="http://feeds.feedburner.com/xm-wordpress-stuff.1.gif" alt="XavierMedia.com - Wordpress Stuff" style="border:0"></a><BR/>

	<h2>Wordpress plugins from Xavier Media&reg;</h2>
	<UL>
	<li><a href="http://wordpress.org/extend/plugins/wp-statusnet/" TARGET="_blank">WP-Status.net</a> - Posts your blog posts to one or multiple Status.net servers and even to Twitter 
	<li><a href="http://wordpress.org/extend/plugins/wp-email-to-facebook/" TARGET="_blank">WP Email-to-Facebook</a> - Posts your blog posts to one or multiple Facebook pages from your WordPress blog 
	<li><a href="http://wordpress.org/extend/plugins/wp-check-spammers/" TARGET="_blank">WP-Check Spammers</a> - Check comment against the SpamBot Search Tool using the IP address, the email and the name of the poster as search criteria 
	<li><a href="http://wordpress.org/extend/plugins/xm-backup/" TARGET="_blank">XM Backup</a> - Do backups of your Wordpress database and files in the uploads folder. Backups can be saved to Dropbox, FTP accounts or emailed
	</UL>

	<?php

}

function wpstatusnet_addoption()
{
	if (function_exists('add_options_page')) 
	{
		add_options_page('WP-Status.net', 'WP-Status.net', 0, basename(__FILE__), 'wpstatusnet_options');
    	}	
}

add_action('admin_menu', 'wpstatusnet_addoption');

?>
