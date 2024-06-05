# CSPBuilder

Generate a CSP header 

## Installation

This project using composer.

```sh
composer require kingsoft/csp-builder
```

## Usage

```php
<?php
use CSP\CspBuilder;

$csp = (new CspBuilder())
  ->addCspPolicy('script-src', CspBuilder::SELF)
  ->addCspPolicy('script-src', CspBuilder::NONCE)
  ->addCspPolicyNonce('script-src')
  ->setCspHeader();

define('NONCE', $csp-> getNonce());

<script nonce="<?= NONCE ?>">
</script>
```
