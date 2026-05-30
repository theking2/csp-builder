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

## Enums

`Source` (directive keys):

- `Source::Default` (`default-src`)
- `Source::Image` (`img-src`)
- `Source::Font` (`font-src`)
- `Source::Script` (`script-src`)
- `Source::Style` (`style-src`)
- `Source::Connect` (`connect-src`)
- `Source::Object` (`object-src`)
- `Source::Frame` (`frame-src`)
- `Source::Base` (`base-uri`)
- `Source::Form` (`form-action`)
- `Source::Manifest` (`manifest-src`)

`Directive` (directive values):

> Note: quoted CSP keywords are already formatted in the enum values
> (for example `Directive::Self` becomes `'self'` in the header).

- `Directive::Self` (`'self'`)
- `Directive::UnsafeInline` (`'unsafe-inline'`)
- `Directive::UnsafeEval` (`'unsafe-eval'`)
- `Directive::Data` (`data:`)
- `Directive::Blob` (`blob:`)
- `Directive::Media` (`media:`)
- `Directive::Frame` (`frame:`)
