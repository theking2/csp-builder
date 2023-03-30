# CSPBuilder
Generate a CSP header 

## Installation
This project using composer.
```
$ composer require theking2/csp-builder
```

## Usage
 * Example:
```php
<?php
use CSP\CspBuilder;

$csp = new CspBuilder();
$csp->addCspPolicies('default-src', [CspBuilder::SELF]);
->addCspPolicy('script-src', CspBuilder::SELF)
->addCspPolicy('script-src', CspBuilder::NONCE)
->addCspPolicyNonce('script-src')
->setCspHeader();

define('NONCE', $csp-> getNonce());


```