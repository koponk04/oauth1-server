<?php

use JoakimKejser\OAuth\ConsumerInterface;
use JoakimKejser\OAuth\OauthRequest;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request as SymfonyRequest;

class RequestTest extends TestCase
{
	public function testToStringNoParameters(): void
	{
		$request = new JoakimKejser\OAuth\OauthRequest('GET', 'http://localhost/index.php');

		$this->assertEquals('http://localhost/index.php', (string) $request);
	}

	public function testToStringWithParameters(): void
	{
		$request = new OauthRequest('GET', 'http://localhost/index.php', ['a' => '123', 'q' => 'as', 'c' => '321']);

		$this->assertEquals('http://localhost/index.php?a=123&c=321&q=as', (string) $request);
	}

	public function testCreateFromRequest(): void
	{
		$request = $this->getRequest();

		$this->assertEquals(new OauthRequest('GET', 'http://localhost/index.php'), $request);
	}

	public function testCreateFromRequestPost(): void
	{
		$request = OauthRequest::createFromRequest(SymfonyRequest::create('/index.php', 'POST', [], [], [], [], 'data=lotsofdata&action=doit'));

		$this->assertEquals(new OauthRequest('POST', 'http://localhost/index.php', ['data' => 'lotsofdata', 'action' => 'doit']), $request);
		$this->assertEquals('lotsofdata', $request->getParameter('data'));
		$this->assertEquals('doit', $request->getParameter('action'));
	}

	public function testCreateFromConsumerAndToken()
	{
		$consumer = new Consumer(['key' => 'key', 'secret' => 'secret']);

		$request = OauthRequest::createFromConsumerAndToken($consumer, 'GET', 'http://localhost/index.php');

		$this->assertEquals('key', $request->getParameter('oauth_consumer_key'));
		$this->assertEquals(OauthRequest::$version, $request->getParameter('oauth_version'));
		$this->assertTrue(null != $request->getParameter('oauth_nonce'));
		$this->assertTrue(is_int($request->getParameter('oauth_timestamp')));
		$this->assertTrue(null != $request->getParameter('oauth_timestamp'));

		return $request;
	}

	public function testCreateWithAuthorizationHeader(): void
	{
		$consumer = new Consumer(['key' => 'key', 'secret' => 'secret']);

		$request = OauthRequest::createFromConsumerAndToken($consumer, 'GET', 'http://localhost/index.php', null, ['foo' => 'bar']);

		$request->sign(new JoakimKejser\OAuth\SignatureMethod\HmacSha1(), $consumer, null);

		// Strip the Authorization part as we will be providing the header directly to the OauthRequest as HTTP_AUTHORIZATION
		$authHeader = str_replace('Authorization: ', '', $request->toHeader());

		$server = ['HTTP_AUTHORIZATION' => $authHeader];

		$sRequest = SymfonyRequest::create('/index.php', 'POST', [], [], [], $server);

		$request2 = OauthRequest::createFromRequest($sRequest);

		$this->assertNotNull($request2->getParameter('oauth_signature'));
		$this->assertNotNull($request2->getParameter('oauth_version'));
		$this->assertNotNull($request2->getParameter('oauth_consumer_key'));
		$this->assertNotNull($request2->getParameter('oauth_timestamp'));
		$this->assertNotNull($request2->getParameter('oauth_nonce'));
		$this->assertNotNull($request2->getParameter('oauth_signature_method'));

		$this->assertNull($request2->getParameter('oauth_token'));
	}

	/**
	 * @depends testCreateFromConsumerAndToken
	 */
	public function testToHeaderWithRealm(OauthRequest $request): void
	{
		$this->assertEquals('realm="testRealm"', substr($request->toHeader('testRealm'), 21, 17));
	}

	/**
	 * @depends testCreateFromConsumerAndToken
	 */
	public function testSigningRequest(OauthRequest $request): void
	{
		$signatureMethod = new JoakimKejser\OAuth\SignatureMethod\HmacSha1();

		$consumer = new Consumer(['key' => 'key', 'secret' => 'secret']);

		$this->assertNull($request->getParameter('oauth_signature'));
		$this->assertNull($request->getParameter('oauth_signature_method'));

		$request->sign($signatureMethod, $consumer);

		$oldSig = $request->getParameter('oauth_signature');

		$this->assertEquals('HMAC-SHA1', $request->getParameter('oauth_signature_method'));
		$this->assertEquals(28, strlen($request->getParameter('oauth_signature')));

		$request->sign($signatureMethod, $consumer);

		$this->assertEquals($oldSig, $request->getParameter('oauth_signature'));
	}

	/**
	 * @depends testCreateFromConsumerAndToken
	 */
	public function testArraysInParameters(OauthRequest $request): void
	{
		$request->setParameter('oauth_signature', [$request->getParameter('oauth_signature')]);

		try {
			$request->toHeader();
		} catch (JoakimKejser\OAuth\Exception $e) {
			$this->assertTrue($e instanceof JoakimKejser\OAuth\Exception\ArrayNotSupportedInHeadersException);
		}
	}

	public function testCreateFromConsumerAndTokenWithToken(): void
	{
		$token = new JoakimKejser\OAuth\AccessToken('tokenkey', 'tokensecret');
		$consumer = new Consumer(['key' => 'key', 'secret' => 'secret']);
		$request = OauthRequest::createFromConsumerAndToken($consumer, 'GET', 'http://localhost/index.php', $token, ['foo' => 'bar']);

		$this->assertEquals('tokenkey', $request->getParameter('oauth_token'));
	}

	public function testCreateFromGlobals(): void
	{
		$_SERVER = [
			'HTTP_HOST' => 'localhost',
			'SERVER_PORT' => 80,
			'REQUEST_METHOD' => 'GET',
			'REQUEST_URI' => '/index.php'
		];

		$request = OauthRequest::createFromGlobals();

		$this->assertEquals(new OauthRequest('GET', 'http://localhost/index.php'), $request);
	}

	public function testGetNormalizedUri(): void
	{
		$symfonyRequest = SymfonyRequest::create('http://localhost:80/index.php', 'GET');
		$request = OauthRequest::createFromRequest($symfonyRequest);

		$url = $request->getNormalizedHttpUrl();

		$this->assertEquals('http://localhost/index.php', $url);

		$symfonyRequest = SymfonyRequest::create('http://localhost:8080/index.php', 'GET');
		$request = OauthRequest::createFromRequest($symfonyRequest);

		$url = $request->getNormalizedHttpUrl();

		$this->assertEquals('http://localhost:8080/index.php', $url);
	}

	public function testUnsetParameter(): void
	{
		$request = $this->getRequest();

		$request->setParameter('foo', 'bar');

		$this->assertEquals($request->getParameter('foo'), 'bar');

		$request->unsetParameter('foo');

		$this->assertEquals($request->getParameter('foo'), null);
	}

	public function testSetParameter(): void
	{
		$request = $this->getRequest();

		$request->setParameter('foo', 'bar');

		$this->assertEquals($request->getParameter('foo'), 'bar');

		$request->setParameter('foo', 'baz', true);

		$this->assertEquals($request->getParameter('foo'), ['bar', 'baz']);
	}

	public function testToPostDataNoOAuth(): void
	{
		$consumer = new Consumer(['key' => 'key', 'secret' => 'secret']);

		$request = OauthRequest::createFromConsumerAndToken($consumer, 'POST', 'http://localhost/index.php', null, ['foo' => 'bar']);

		$request->sign(new JoakimKejser\OAuth\SignatureMethod\HmacSha1(), $consumer, null);

		$postDataParameters = JoakimKejser\OAuth\Util::parseParameters($request->toPostData(true));

		$this->assertFalse(array_key_exists('oauth_signature', $postDataParameters));
		$this->assertTrue(array_key_exists('foo', $postDataParameters));
	}

	protected function getRequest($httpMethod = null, $httpUrl = null, $parameters = null)
	{
		return OauthRequest::createFromRequest(SymfonyRequest::create('/index.php', 'GET'));
	}
}

if (!class_exists('Consumer')) {
	class Consumer implements ConsumerInterface
	{
		protected $data;

		public function __construct(array $data)
		{
			$this->data = $data;
		}

		public function getValue($field)
		{
			if (isset($this->data[$field])) {
				return $this->data[$field];
			}

			return null;
		}

		public function getKey()
		{
			return $this->getValue('key');
		}

		public function getSecret()
		{
			return $this->getValue('secret');
		}
	}
}
