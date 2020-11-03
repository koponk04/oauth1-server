<?php
namespace JoakimKejser\OAuth;

use Symfony\Component\HttpFoundation\Request as SymfonyRequest;

/**
 * Class OauthRequest.
 */
class OauthRequest
{
	public static $version = '1.0';

	// for debug purposes
	public $baseString;
	protected $parameters;
	protected $httpMethod;
	protected $httpUrl;

	public function __construct($httpMethod, $httpUrl, $parameters = null)
	{
		$parameters = ($parameters) ? $parameters : [];
		$parameters = array_merge(Util::parseParameters(parse_url($httpUrl, PHP_URL_QUERY)), $parameters);
		$this->parameters = $parameters;
		$this->httpMethod = $httpMethod;
		$this->httpUrl = $httpUrl;
	}

	/**
	 * tostring.
	 *
	 * @return string
	 */
	public function __toString()
	{
		$toUrl = $this->toUrl();

		return $toUrl;
	}

	/**
	 * Attempt to buid a OauthRequest from a Symfony OauthRequest object.
	 *
	 * @param \Symfony\Component\HttpFoundation\Request $symfonyRequest
	 * @param string                                    $httpMethod     Override of the HTTP Method
	 * @param string                                    $httpUrl        Override of the HTTP URL
	 * @param array                                     $parameters     An array of parameters
	 *
	 * @return OauthRequest
	 */
	public static function createFromRequest(
		SymfonyRequest $symfonyRequest,
		$httpMethod = null,
		$httpUrl = null,
		$parameters = null
	) {
		$httpUrl = ($httpUrl) ? $httpUrl : $symfonyRequest->getSchemeAndHttpHost() . $symfonyRequest->getRequestUri();
		$httpMethod = ($httpMethod) ? $httpMethod : $symfonyRequest->getMethod();

		// We weren't handed any parameters, so let's find the ones relevant to
		// this request.
		// If you run XML-RPC or similar you should use this to provide your own
		// parsed parameter-list
		if (!$parameters) {
			// Find request headers
			$requestHeaders = Util::getHeaders($symfonyRequest);

			// Parse the query-string to find GET parameters
			$parameters = Util::parseParameters($symfonyRequest->getQueryString());

			// It's a POST request of the proper content-type, so parse POST
			// parameters and add those overriding any duplicates from GET
			if ('POST' == $httpMethod) {
				if (isset($requestHeaders['Content-Type']) and strstr(
					$requestHeaders['Content-Type'],
					'application/x-www-form-urlencoded'
				)
				) {
					$postData = Util::parseParameters(
						$symfonyRequest->getContent()
					);
					$parameters = array_merge($parameters, $postData);
				} else {
					$postData = $symfonyRequest->request->all();
					$parameters = array_merge($parameters, $postData);
				}
			}

			// We have a Authorization-header with OAuth data. Parse the header
			// and add those overriding any duplicates from GET or POST
			if (isset($requestHeaders['Authorization']) and 'OAuth ' == substr($requestHeaders['Authorization'], 0, 6)
			) {
				$headerParameters = Util::splitHeader($requestHeaders['Authorization']);
				$parameters = array_merge($parameters, $headerParameters);
			}
		}

		$oauthRequest = new OauthRequest($httpMethod, $httpUrl, $parameters);

		return $oauthRequest;
	}

	/**
	 * Create the OauthRequest object from globals.
	 *
	 * @param string $httpMethod Override of the HTTP Method
	 * @param string $httpUrl    Override of the HTTP Url
	 * @param array  $parameters Array of parameters
	 *
	 * @return OauthRequest
	 */
	public static function createFromGlobals($httpMethod = null, $httpUrl = null, $parameters = null)
	{
		$oauthRequest = OauthRequest::createFromRequest(SymfonyRequest::createFromGlobals(), $httpMethod, $httpUrl, $parameters);

		return $oauthRequest;
	}

	/**
	 * Creates a OauthRequest form consumer and token.
	 *
	 * @param ConsumerInterface $consumer
	 * @param string            $httpMethod
	 * @param string            $httpUrl
	 * @param TokenInterface    $token
	 * @param array             $parameters
	 *
	 * @return OauthRequest
	 */
	public static function createFromConsumerAndToken(
		ConsumerInterface $consumer,
		$httpMethod,
		$httpUrl,
		TokenInterface $token = null,
		$parameters = null
	) {
		$parameters = ($parameters) ? $parameters : [];
		$defaults = [
			'oauth_version' => OauthRequest::$version,
			'oauth_nonce' => OauthRequest::generateNonce(),
			'oauth_timestamp' => OauthRequest::generateTimestamp(),
			'oauth_consumer_key' => $consumer->getKey()
		];

		if ($token) {
			$defaults['oauth_token'] = $token->getKey();
		}

		$parameters = array_merge($defaults, $parameters);

		$authRequest = new OauthRequest($httpMethod, $httpUrl, $parameters);

		return $authRequest;
	}

	/**
	 * Sets a parameter on the OauthRequest object.
	 *
	 * @param string $name
	 * @param mixed  $value
	 * @param bool   $allowDuplicates
	 */
	public function setParameter($name, $value, $allowDuplicates = true): void
	{
		if ($allowDuplicates and isset($this->parameters[$name])) {
			// We have already added parameter(s) with this name, so add to the list
			if (is_scalar($this->parameters[$name])) {
				// This is the first duplicate, so transform scalar (string)
				// into an array so we can add the duplicates
				$this->parameters[$name] = [$this->parameters[$name]];
			}

			$this->parameters[$name][] = $value;
		} else {
			$this->parameters[$name] = $value;
		}
	}

	/**
	 * Gets a parameters from the OauthRequest object.
	 *
	 * @param string $name
	 *
	 * @return mixed
	 */
	public function getParameter($name)
	{
		$parameter = isset($this->parameters[$name]) ? $this->parameters[$name] : null;

		return $parameter;
	}

	/**
	 * Gets all parameters.
	 *
	 * @return array
	 */
	public function getParameters()
	{
		return $this->parameters;
	}

	/**
	 * Deletes a parameter.
	 *
	 * @param string $name [description]
	 */
	public function unsetParameter($name): void
	{
		unset($this->parameters[$name]);
	}

	/**
	 * The request parameters, sorted and concatenated into a normalized string.
	 *
	 * @return string
	 */
	public function getSignableParameters()
	{
		// Grab all parameters
		$params = $this->parameters;

		// Remove oauth_signature if present
		// Ref: Spec: 9.1.1 ("The oauth_signature parameter MUST be excluded.")
		if (isset($params['oauth_signature'])) {
			unset($params['oauth_signature']);
		}

		$httpQuery = Util::buildHttpQuery($params);

		return $httpQuery;
	}

	/**
	 * Returns the base string of this request.
	 *
	 * The base string defined as the method, the url
	 * and the parameters (normalized), each urlencoded
	 * and the concated with &.
	 *
	 * @return string
	 */
	public function getSignatureBaseString()
	{
		$parts = [
			$this->getNormalizedHttpMethod(),
			$this->getNormalizedHttpUrl(),
			$this->getSignableParameters()
		];

		$parts = Util::urlencodeRfc3986($parts);

		$signatureBaseString = implode('&', $parts);

		return $signatureBaseString;
	}

	/**
	 * Just uppercases the HTML Method.
	 *
	 * @return string
	 */
	public function getNormalizedHttpMethod()
	{
		$normalizedHttpMethod = strtoupper($this->httpMethod);

		return $normalizedHttpMethod;
	}

	/**
	 * Parses the URL and rebuilds it to be scheme://host/path.
	 *
	 * @return string
	 */
	public function getNormalizedHttpUrl()
	{
		$parts = parse_url($this->httpUrl);

		$scheme = (isset($parts['scheme'])) ? $parts['scheme'] : 'http';
		$port = (isset($parts['port'])) ? $parts['port'] : (('https' == $scheme) ? '443' : '80');
		$host = (isset($parts['host'])) ? strtolower($parts['host']) : '';
		$path = (isset($parts['path'])) ? $parts['path'] : '';

		if (('https' == $scheme and '443' != $port) or ('http' == $scheme and '80' != $port)) {
			$host = "${host}:${port}";
		}

		return "${scheme}://${host}${path}";
	}

	/**
	 * Build URL for GET request.
	 *
	 * @param bool $noOAuthParameters
	 *
	 * @return string
	 */
	public function toUrl($noOAuthParameters = false)
	{
		$postData = $this->toPostdata($noOAuthParameters);
		$out = $this->getNormalizedHttpUrl();
		if ($postData) {
			$out .= '?' . $postData;
		}

		return $out;
	}

	/**
	 * Build the data for a POST request.
	 *
	 * @param bool $noOAuthParameters Whether or not to include OAuth parameters. To use when parameters are passed in the Authorization header.
	 *
	 * @return string
	 */
	public function toPostData($noOAuthParameters = false)
	{
		$parameters = $this->getParameters();
		if (true === $noOAuthParameters) {
			foreach ($parameters as $k => $v) {
				if ('oauth' == substr($k, 0, 5)) {
					unset($parameters[$k]);
				}
			}
		}

		$httpQuery = Util::buildHttpQuery($parameters);

		return $httpQuery;
	}

	/**
	 * Build the Authorization header.
	 *
	 * @param string $realm
	 *
	 * @throws Exception\ArrayNotSupportedInHeadersException
	 *
	 * @return string
	 */
	public function toHeader($realm = null)
	{
		$first = true;
		if ($realm) {
			$out = 'Authorization: OAuth realm="' . Util::urlencodeRfc3986($realm) . '"';
			$first = false;
		} else {
			$out = 'Authorization: OAuth';
		}

		$total = [];
		foreach ($this->parameters as $k => $v) {
			if ('oauth' != substr($k, 0, 5)) {
				continue;
			}
			if (is_array($v)) {
				throw new Exception\ArrayNotSupportedInHeadersException();
			}
			$out .= ($first) ? ' ' : ',';
			$out .= Util::urlencodeRfc3986($k) . '="' . Util::urlencodeRfc3986($v) . '"';
			$first = false;
		}

		return $out;
	}

	/**
	 * Function for signing the OauthRequest object.
	 *
	 * @param SignatureMethod   $signatureMethod
	 * @param ConsumerInterface $consumer
	 * @param TokenInterface    $token
	 */
	public function sign(SignatureMethod $signatureMethod, ConsumerInterface $consumer, TokenInterface $token = null): void
	{
		$this->setParameter(
			'oauth_signature_method',
			$signatureMethod->getName(),
			false
		);
		$signature = $this->buildSignature($signatureMethod, $consumer, $token);
		$this->setParameter('oauth_signature', $signature, false);
	}

	/**
	 * Builds the actual signature.
	 *
	 * @param SignatureMethod   $signatureMethod
	 * @param ConsumerInterface $consumer
	 * @param TokenInterface    $token
	 *
	 * @return string
	 */
	public function buildSignature(
		SignatureMethod $signatureMethod,
		ConsumerInterface $consumer,
		TokenInterface $token = null
	) {
		$signature = $signatureMethod->buildSignature($this, $consumer, $token);

		return $signature;
	}

	/**
	 * Sets the basestring.
	 *
	 * @param string $baseString
	 */
	public function setBaseString($baseString): void
	{
		$this->baseString = $baseString;
	}

	/**
	 * Utility function: returns current timestamp.
	 *
	 * @return int
	 */
	private static function generateTimestamp()
	{
		$timestamp = time();

		return $timestamp;
	}

	/**
	 * Utility function: generates the current nonce.
	 *
	 * @return string
	 */
	private static function generateNonce()
	{
		$mt = microtime();
		$rand = mt_rand();

		$nonce = md5($mt . $rand); // md5s look nicer than numbers
		return $nonce;
	}
}
