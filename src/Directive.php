<?php declare(strict_types=1);

namespace Kingsoft\Csp;

/**
 * Directive
 * CSP directives
 */
enum Directive: String {
  case Self = "'self'";
  case UnsafeInline = "'unsafe-inline'";
  case UnsafeEval = "'unsafe-eval'";
  case Data = "data:";
  case Blob = "blob:";
  case Media = "media:";
  case Frame = "frame:";
}