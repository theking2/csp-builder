<?php declare(strict_types=1);

namespace Kingsoft\Csp;

/**
 * CspSource
 * CSP sources
 */
enum Source: String {
  case Default = "default-src";
  case Image = "img-src";
  case Font = "font-src";
  case Script = "script-src";
  case Style = "style-src";
  case Connect = "connect-src";
  case Object = "object-src";
  case Frame = "frame-src";
  case Base = "base-uri";
  case Form = "form-action";
  case Manifest = "manifest-src";
}