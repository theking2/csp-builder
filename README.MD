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

$builder = (new Builder())
  ->addCspPolicy(Source::Script, Directive::Self)
  ->addCspPolicyNonce(Source::Script)
  ->addCspPolicyUrl(Source::Script, 'https://cdn.example.com');

$builder->setCspHeader();
$nonce = $builder->getNonce();
```

```html
<script nonce="<?= htmlspecialchars($nonce, ENT_QUOTES, 'UTF-8') ?>"></script>
```

You can also build the header string without sending it:

```php
$header = $builder->getCspHeader();
```

To initialize all supported sources with `'self'` by default:

```php
$builder = new Builder(true);
```
