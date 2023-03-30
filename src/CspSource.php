<?php declare(strict_types=1);
namespace CSP;

/**
 * CspSource
 * CSP sources
 */
enum CspSource: String {
  case Default = "default-src";
  case Image = "img-src";
  case Font = "font-src";
  case Script = "script-src";
  case Style = "style-src";
}