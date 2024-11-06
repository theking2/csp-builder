<?php declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use Kingsoft\Csp\{Builder, Directive, Source};


class BuilderTest extends TestCase
{
    public function testConstructorGeneratesNonce()
    {
        $builder = new Builder();
        $nonce = $builder->getNonce();
        $this->assertNotEmpty($nonce);
        $this->assertEquals(64, strlen($nonce)); // Base64 encoded 46 bytes should be 64 characters
    }

    public function testAddCspPolicy()
    {
        $builder = new Builder();
        $builder->addCspPolicy(Source::Script, Directive::Self);
        $header = $builder->getCspHeader();
        $this->assertStringContainsString("script-src 'self'", $header);
    }

    public function testAddCspPolicyUrl()
    {
        $builder = new Builder();
        $builder->addCspPolicyUrl(Source::Script, 'https://example.com');
        $header = $builder->getCspHeader();
        $this->assertStringContainsString("script-src https://example.com", $header);
    }

    public function testAddCspPolicyNonce()
    {
        $builder = new Builder();
        $builder->addCspPolicyNonce(Source::Script);
        $nonce = $builder->getNonce();
        $header = $builder->getCspHeader();
        $this->assertStringContainsString("script-src 'nonce-$nonce'", $header);
    }
}