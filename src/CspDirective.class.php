<?php declare(strict_types=1);

namespace CSP;

/**
 * CspDirective
 * CSP directives
 */
enum CspDirective: String {
  case Self = "'self'";
  case UnsafeInline = "'unsafe-inline'";
  case UnsafeEval = "'unsafe-eval'";
  case Data = "data:";
  case Blob = "blob:";
  case Media = "media:";
  case Frame = "frame:";
}