<?php

namespace Kotarb\Push;

use Exception;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Client;
use Psr\Http\Message\ResponseInterface;
use GuzzleHttp\Exception\RequestException;
use Minishlink\WebPush\Encryption;
use Minishlink\WebPush\VAPID;

class Push
{
    public const PUBLIC_KEY_LENGTH = 65;
    public const PRIVATE_KEY_LENGTH = 32;

    private $_config = [];

    public function __construct(array $config)
    {
        $this->_config = $config;
    }

    function go()
    {

        $message = $this->_config['message'];

        $vapid = [
            'subject' => $this->_config['vapid']['email'],
            'publicKey' => $this->_config['vapid']['publicKey'],
            'privateKey' => $this->_config['vapid']['privateKey']
        ];

        $payloadLen = mb_strlen($message, '8bit');
        $padLen = 3052 - $payloadLen;

        // aesgcm
        //$payload = pack('n*', $padLen) . str_pad($message, $padLen + $payloadLen, chr(0), STR_PAD_LEFT);

        // aes128gcm
        $payload = str_pad($message.chr(2), $padLen + $payloadLen, chr(0), STR_PAD_RIGHT);

        $publicKey = $this->Base64UrlDecode($vapid['publicKey']);

        if ( $this->safeStrlen($publicKey) !== self::PUBLIC_KEY_LENGTH) {
            throw new Exception('[VAPID] Public key should be 65 bytes long when decoded.');
        }

        if (!isset($vapid['privateKey'])) {
            throw new Exception('[VAPID] You must provide a private key.');
        }

        $privateKey = $this->Base64UrlDecode($vapid['privateKey']);

        if ($this->safeStrlen($privateKey) !== self::PRIVATE_KEY_LENGTH) {
            throw new Exception('[VAPID] Private key should be 32 bytes long when decoded.');
        }

        $vapid = [
            'subject' => $vapid['subject'],
            'publicKey' => $publicKey,
            'privateKey' => $privateKey,
        ];

        $subscription = json_decode($this->_config['subscription'], true);

        $endpoint = $subscription['endpoint'];
        $userPublicKey = $subscription['p256dh'];
        $userAuthToken = $subscription['auth'];
        $contentEncoding = 'aes128gcm';

        $options = [
            'TTL' => 2419200,
            'urgency' => null,
            'topic' => null,
            'batchSize' => 1000
        ];

        if (!empty($payload) && !empty($userPublicKey) && !empty($userAuthToken)) {
            if (!$contentEncoding) {
                throw new Exception('Subscription should have a content encoding');
            }

            $encrypted = Encryption::encrypt($payload, $userPublicKey, $userAuthToken, $contentEncoding);
            $cipherText = $encrypted['cipherText'];
            $salt = $encrypted['salt'];
            $localPublicKey = $encrypted['localPublicKey'];

            $headers = [
                'Content-Type' => 'application/octet-stream',
                'Content-Encoding' => $contentEncoding,
            ];

            $encryptionContentCodingHeader = Encryption::getContentCodingHeader($salt, $localPublicKey, $contentEncoding);
            $content = $encryptionContentCodingHeader . $cipherText;

            $headers['Content-Length'] = $this->safeStrlen($content);
        } else {
            $headers = [
                'Content-Length' => 0,
            ];

            $content = '';
        }

        $headers['TTL'] = $options['TTL'];

        if (isset($options['urgency'])) {
            $headers['Urgency'] = $options['urgency'];
        }

        if (isset($options['topic'])) {
            $headers['Topic'] = $options['topic'];
        }

        $audience = parse_url($endpoint, PHP_URL_SCHEME) . '://' . parse_url($endpoint, PHP_URL_HOST);
        if (!parse_url($audience)) {
            throw new Exception('Audience "' . $audience . '"" could not be generated.');
        }

        $vapidHeaders = VAPID::getVapidHeaders($audience, $vapid['subject'], $vapid['publicKey'], $vapid['privateKey'], $contentEncoding);

        $headers['Authorization'] = $vapidHeaders['Authorization'];

        $request = new Request('POST', $endpoint, $headers, $content);

        $client = new Client(['timeout' => 30]);

        $promise = $client->sendAsync($request)
            ->then(function ($response) use ($request) {
                /** @var ResponseInterface $response * */
                //return new MessageSentReport($request, $response);
                echo $response->getStatusCode(), PHP_EOL,
                $response->getBody(), PHP_EOL,
                json_encode($response->getHeaders()), PHP_EOL;
            })
            ->otherwise(function ($reason) {
                /** @var RequestException $reason * */
                //return new MessageSentReport($reason->getRequest(), $reason->getResponse(), false, $reason->getMessage());
                echo $reason->getCode(), PHP_EOL, $reason->getMessage(), PHP_EOL, $reason->getTraceAsString();
            });

        $promise->wait();
    }

    function safeStrlen(string $value): int
    {
        return mb_strlen($value, '8bit');
    }

    function Base64UrlDecode($data)
    {
        $decoded = base64_decode(strtr($data, '-_', '+/'), true);
        if ($decoded === false) {
            throw new Exception('Invalid data provided');
        }

        return $decoded;
    }

    function Base64UrlEncode(string $data, bool $usePadding = false): string
    {
        $encoded = strtr(base64_encode($data), '+/', '-_');

        return true === $usePadding ? $encoded : rtrim($encoded, '=');
    }

}