# CSP Builder

Build Content-Security-Policy (CSP) headers in PHP.

## Installation

Install with Composer:

```sh
composer require kingsoft/csp-builder
```

## Usage

```php
<?php

use Kingsoft\Csp\{Builder, Directive, Source};

// API order: Source is the CSP directive name (e.g. script-src),
// Directive is the value (e.g. 'self').
$builder = (new Builder())
  ->addCspPolicy(Source::Script, Directive::Self)
  ->addCspPolicyNonce(Source::Script)
  ->addCspPolicyUrl(Source::Script, 'https://cdn.example.com');

$builder->setCspHeader();
$nonce = $builder->getNonce();

// addCspPolicyNonce() adds the nonce token to script-src,
// getNonce() returns the same token for use in your HTML tags.
```

```html
<script nonce="<?= $nonce ?>"></script>
```

You can also build the header string without sending it:

```php
$header = $builder->getCspHeader();
```

To initialize all supported sources with `'self'` by default:

```php
$builder = new Builder(true);
```
