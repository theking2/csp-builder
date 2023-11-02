# CSPBuilder
Generate a CSP header 

## Installation
This project using composer.
```
$ composer require kingsoft/csp-builder
```

## Usage
 * Example:
```php
<?php
use CSP\CspBuilder;

$csp = (new CspBuilder())
  ->addCspPolicy('script-src', CspBuilder::SELF)
  ->addCspPolicy('script-src', CspBuilder::NONCE)
  ->addCspPolicyNonce('script-src')
  ->setCspHeader();

define('NONCE', $csp-> getNonce());


```
