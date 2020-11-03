<?php
namespace JoakimKejser\OAuth;

interface TokenStoreInterface
{
    /**
     * @param ConsumerInterface $consumer
     * @param $tokenType
     * @param $tokenField
     * @return mixed
     */
    public function getToken(ConsumerInterface $consumer, $tokenType, $tokenField);

    /**
     * @param ConsumerInterface $consumer
     * @param null $callback
     * @return TokenInterface
     */
    public function newRequestToken(ConsumerInterface $consumer, $callback = null);

    /**
     * @param TokenInterface $requestToken
     * @param ConsumerInterface $consumer
     * @param null $verifier
     * @return TokenInterface access token
     */
    public function newAccessToken(TokenInterface $requestToken, ConsumerInterface $consumer, $verifier = null);
}
