<?php declare(strict_types=1);

namespace Kingsoft\Csp;

/**
 * Builder
 * Build a Content Security Policy (CSP) header
 * Example:
 * $Csp = (new Builder())
 *  ->addCspPolicy('script-src', Builder::SELF);
 *  ->addCspPolicyNonce('script-src');
 */
class Builder
{  
  private string $nonce;
  private array $csp_options = [];
  
  public function __construct(?bool $defaultSelf=false)
  {
    $strong = false;
    $this->nonce = base64_encode(openssl_random_pseudo_bytes( 46, $strong ));
    if( !$strong ) {
      error_log("weak random for nonce");
    }
    if( $defaultSelf )
      foreach( Source::cases() as $source )
        $this->csp_options[ $source->value ][] = Directive::Self-> value;
    else
  	  $this->csp_options = [];
  }  
  /**
   * Add a complete source list to the CSP
   * @deprecated use addCspPolicy
   *
   * @param  Source $source
   * @param  array $directivess Array of string directives
   * @return Builder for chaining
   */
  public function addCspPolicies(Source $source, array $directives): Builder
  {
    $this->csp_options[ $source-> value ] = $directives;
    return $this;
  }  
  /**
   * Add a single source to the CSP
   *
   * @param  Source $source
   * @param  Directive $directive
   * @return Builder for chainning
   */
  public function addCspPolicy(Source $source, Directive $directive): Builder
  {
    $this->csp_options[ $source-> value ][] = $directive-> value;
    return $this;
  }
    /**
   * Add a single url to the CSP
   *
   * @param  Source $source
   * @param  string  $url
   * @return Builder for chainning
   */
  public function addCspPolicyUrl(Source $source, string $url): Builder
  {
    $this->csp_options[ $source-> value ][] = $url;
    return $this;
  }  
  /**
   * Add a nonce policy
   *
   * @param  Source $source
   * @return Builder for chaining
   */
  public function addCspPolicyNonce(Source $source) : Builder
  {
    $this->csp_options[ $source-> value ][] = "'nonce-$this->nonce'";
    return $this;
  }
  /**
   * return the current nonce
   * @return string
   */
  public function getNonce(): string
  {
    return $this->nonce;
  }    
  /**
   * create a complete policy
   *
   * @return string
   */
  public function getCspHeader(): string
  {
    $result = '';
    foreach ($this->csp_options as $source => $sources) {
      $result .= $source . ' ' . implode(' ', $sources) . '; ';
    
    }
    return $result;
  }  
  /**
   * setCspHeader
   * Side effect set the header in the current request
   *
   * @return Builder
   */
  public function setCspHeader(): Builder
  {
    header('Content-Security-Policy: ' . $this->getCspHeader());

    return $this;
  }

}
