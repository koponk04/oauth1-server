<?php
namespace JoakimKejser\OAuth;

/**
 * Class Server
 * @package JoakimKejser\OAuth
 */
class Server
{
    /**
     * @var int seconds
     */
    protected $timestampThreshold = 300;

    /**
     * @var string
     */
    protected $version = '1.0';

    /**
     * @var array
     */
    protected $signatureMethods = array();

    /**
     * @var ConsumerStoreInterace
     */
    protected $consumerStore;
    /**
     * @var NonceStoreInterface
     */
    protected $nonceStore;

    /**
     * @var TokenStoreInterface
     */
    protected $tokenStore;

    /**
     * Constructor
     * @param OauthRequest $request
     * @param ConsumerStoreInterface $consumerStore
     * @param NonceStoreInterface $nonceStore
     * @param TokenStoreInterface $tokenStore
     */
    public function __construct(
        OauthRequest $request,
        ConsumerStoreInterface $consumerStore,
        NonceStoreInterface $nonceStore,
        TokenStoreInterface $tokenStore = null
    ) {
        $this->request = $request;
        $this->consumerStore = $consumerStore;
        $this->nonceStore = $nonceStore;
        $this->tokenStore = $tokenStore;
    }

    /**
     * Adds a signature method to the server object
     *
     * Adds the signature method to the supported signature methods
     *
     * @param SignatureMethod $signatureMethod
     */
    public function addSignatureMethod(SignatureMethod $signatureMethod)
    {
        $this->signatureMethods[$signatureMethod->getName()] = $signatureMethod;
    }

    /**
     * process a request_token request
     * @return array consumer, request token, and oauth callback on success
     */
    public function fetchRequestToken()
    {
        $this->getVersion();

        $consumer = $this->getConsumer();

        // no token required for the initial token request
        $token = null;

        $this->checkSignature($consumer, $token);

        // Rev A change
        $callback = $this->request->getParameter('oauth_callback');
        $newToken = $this->tokenStore->newRequestToken($consumer, $callback);

        return array($consumer, $newToken, $callback);
    }

    /**
     * process an access_token request
     * @return array consumer, token, and verifier on success
     */
    public function fetchAccessToken()
    {
        $this->getVersion();

        $consumer = $this->getConsumer();

        // requires authorized request token
        $token = $this->getToken($consumer, TokenType::REQUEST);

        $this->checkSignature($consumer, $token);

        // Rev A change
        $verifier = $this->request->getParameter('oauth_verifier');
        $newToken = $this->tokenStore->newAccessToken($token, $consumer, $verifier);

        return array($consumer, $newToken, $verifier);
    }

    /**
     * verify an api call, checks all the parameters
     * @return array consumer and token
     */
    public function verifyRequest()
    {
        $this->getVersion();
        $consumer = $this->getConsumer();
        $token = $this->getToken($consumer, TokenType::ACCESS);
        $this->checkSignature($consumer, $token);

        return array($consumer, $token);
    }

    /**
     * version 1
     */
    private function getVersion()
    {
        $version = $this->request->getParameter("oauth_version");
        if (!$version) {
            // Service Providers MUST assume the protocol version to be 1.0 if this parameter is not present.
            // Chapter 7.0 ("Accessing Protected Ressources")
            $version = '1.0';
        }
        if ($version !== $this->version) {
            throw new Exception\VersionNotSupportedException();
        }

        return $version;
    }

    /**
     * figure out the signature with some defaults
     * @throws Exception\SignatureMethodMissing
     * @throws Exception\SignatureMethodNotSupportedException
     * @return SignatureMethod
     */
    private function getSignatureMethod()
    {
        $signatureMethod = $this->request->getParameter("oauth_signature_method");

        if (!$signatureMethod) {
            // According to chapter 7 ("Accessing Protected Ressources") the signature-method
            // parameter is required, and we can't just fallback to PLAINTEXT
            throw new Exception\SignatureMethodMissing();
        }

        if (!in_array($signatureMethod, array_keys($this->signatureMethods))) {
            throw new Exception\SignatureMethodNotSupportedException(
                "Signature method '$signatureMethod' not supported, try one of the following: " .
                implode(", ", array_keys($this->signatureMethods))
            );
        }

        return $this->signatureMethods[$signatureMethod];
    }

    /**
     * try to find the consumer for the provided request's consumer key
     * @throws Exception\ConsumerKeyMissingException
     * @throws Exception\InvalidConsumerException
     * @return ConsumerInterface
     */
    private function getConsumer()
    {
        $consumerKey = $this->request->getParameter("oauth_consumer_key");

        if (!$consumerKey) {
            throw new Exception\ConsumerKeyMissingException();
        }

        $consumer = $this->consumerStore->getConsumer($consumerKey);
        if (!$consumer) {
            throw new Exception\InvalidConsumerException();
        }

        return $consumer;
    }

    /**
     * try to find the token for the provided request's token key
     * @param ConsumerInterface $consumer
     * @param string $tokenType
     * @return mixed|null
     * @throws Exception\InvalidTokenException
     */
    private function getToken(ConsumerInterface $consumer, $tokenType = TokenType::ACCESS)
    {
        if ($this->tokenStore === null) {
            return null;
        }

        $tokenField = $this->request->getParameter('oauth_token');
        if (is_null($tokenField)) {
            return null;
        }

        $token = $this->tokenStore->getToken(
            $consumer,
            $tokenType,
            $tokenField
        );

        if (!$token) {
            throw new Exception\InvalidTokenException("Invalid $tokenType token: $tokenField");
        }

        return $token;
    }

    /**
     * all-in-one function to check the signature on a request
     * should guess the signature method appropriately
     * @param ConsumerInterface $consumer
     * @param TokenInterface $token
     * @throws Exception\InvalidSignatureException
     * @throws Exception\NonceAlreadyUsedException
     * @throws Exception\NonceMissingException
     * @throws Exception\SignatureMethodMissing
     * @throws Exception\SignatureMethodNotSupportedException
     * @throws Exception\TimestampExpiredException
     * @throws Exception\TimestampMissingException
     */
    private function checkSignature(ConsumerInterface $consumer, TokenInterface $token = null)
    {
        // this should probably be in a different method
        $timestamp = $this->request->getParameter('oauth_timestamp');
        $nonce = $this->request->getParameter('oauth_nonce');

        $this->checkTimestamp($timestamp);
        $this->checkNonce($consumer, $nonce, $timestamp, $token);

        $signatureMethod = $this->getSignatureMethod($this->request);

        $signature = $this->request->getParameter('oauth_signature');
        $validSig = $signatureMethod->checkSignature(
            $signature,
            $this->request,
            $consumer,
            $token
        );

        if (!$validSig) {
            $exception = new Exception\InvalidSignatureException();
            $exception->setDebugInfo($this->request->getSignatureBaseString());
            throw $exception;
        }
    }

    /**
     * check that the timestamp is new enough
     * @param int $timestamp
     * @throws Exception\TimestampExpiredException
     * @throws Exception\TimestampMissingException
     */
    private function checkTimestamp($timestamp)
    {
        if (!$timestamp) {
            throw new Exception\TimestampMissingException();
        }

        // verify that timestamp is recentish
        $now = time();
        if (abs($now - $timestamp) > $this->timestampThreshold) {
            throw new Exception\TimestampExpiredException();
        }
    }

    /**
     * check that the nonce is not repeated
     * @param ConsumerInterface $consumer
     * @param string $nonce
     * @param int $timestamp
     * @param TokenInterface $token
     * @throws Exception\NonceAlreadyUsedException
     * @throws Exception\NonceMissingException
     */
    private function checkNonce(ConsumerInterface $consumer, $nonce, $timestamp, TokenInterface $token = null)
    {
        if (!$nonce) {
            throw new Exception\NonceMissingException();
        }

        // verify that the nonce is uniqueish
        $found = $this->nonceStore->lookup(
            $consumer,
            $nonce,
            $timestamp,
            $token
        );

        if ($found) {
            throw new Exception\NonceAlreadyUsedException();
        }
    }
}
