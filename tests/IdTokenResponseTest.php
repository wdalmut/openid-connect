<?php
namespace Corley\OpenId;

use PHPUnit\Framework\TestCase;
use League\OAuth2\Server\AuthorizationValidators\BearerTokenValidator;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\ResponseTypes\BearerTokenResponse;
use League\OpenIdConnectClaims\ClaimsSet;
use Psr\Http\Message\ResponseInterface;
use Zend\Diactoros\Response;
use Zend\Diactoros\ServerRequest;
use Corley\OpenId\IdTokenResponse;
use Corley\OpenId\UserRepositoryInterface;
use Corley\OpenId\ClientEntity;
use Corley\OpenId\ScopeEntity;
use Corley\OpenId\AccessTokenEntity;
use Corley\OpenId\RefreshTokenEntity;

class IdTokenResponseTest extends TestCase
{
    public function testGenerateHttpResponse()
    {
        $claims = new ClaimsSet();
        $claims->setIdentifier(123456789);
        $claims->setEmail("walter.dalmut@gmail.com");
        $claims->setEmailVerified(true);

        $claims->setAddressStreet('Buckingham Palace');
        $claims->setAddressRegion('London');
        $claims->setAddressPostalCode('SW1A 1AA');
        $claims->setAddressCountry('United Kingdom');

        $scope = new ScopeEntity();
        $scope->setIdentifier('email');
        $scopeOidc = new ScopeEntity();
        $scopeOidc->setIdentifier('openid');

        $userRepository = $this->prophesize(UserRepositoryInterface::class);
        $userRepository->getUserClaimsByUserId(123456789, [$scope, $scopeOidc])->willReturn($claims);;

        $responseType = new IdTokenResponse("https://localhost", $userRepository->reveal());
        $responseType->setPrivateKey(new CryptKey('file://' . __DIR__ . '/private.key'));
        $responseType->setEncryptionKey(base64_encode(random_bytes(36)));

        $client = new ClientEntity();
        $client->setIdentifier('clientName');

        $accessToken = new AccessTokenEntity();
        $accessToken->setIdentifier('abcdef');
        $accessToken->setExpiryDateTime((new \DateTime())->add(new \DateInterval('PT1H')));
        $accessToken->setClient($client);
        $accessToken->setUserIdentifier(123456789);
        $accessToken->addScope($scope);
        $accessToken->addScope($scopeOidc);

        $refreshToken = new RefreshTokenEntity();
        $refreshToken->setIdentifier('abcdef');
        $refreshToken->setAccessToken($accessToken);
        $refreshToken->setExpiryDateTime((new \DateTime())->add(new \DateInterval('PT1H')));

        $responseType->setAccessToken($accessToken);
        $responseType->setRefreshToken($refreshToken);

        $response = $responseType->generateHttpResponse(new Response());

        $this->assertTrue($response instanceof ResponseInterface);
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('no-cache', $response->getHeader('pragma')[0]);
        $this->assertEquals('no-store', $response->getHeader('cache-control')[0]);
        $this->assertEquals('application/json; charset=UTF-8', $response->getHeader('content-type')[0]);

        $response->getBody()->rewind();

        $json = json_decode($response->getBody()->getContents());

        $this->assertEquals('Bearer', $json->token_type);
        $this->assertTrue(isset($json->expires_in));
        $this->assertTrue(isset($json->access_token));
        $this->assertTrue(isset($json->refresh_token));
        $this->assertTrue(isset($json->id_token));
    }
}
