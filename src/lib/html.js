'use strict';

const ESCAPES = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
  '`': '&#96;',
  '=': '&#61;',
};

function escapeHtml(value) {
  return String(value).replace(/[&<>"'`=]/g, (char) => ESCAPES[char]);
}

/** Marker for values that are already trusted HTML. */
class SafeHtml {
  constructor(value) {
    this.value = String(value);
  }

  toString() {
    return this.value;
  }
}

/** Wrap HTML that was produced by this application, never user input. */
function raw(value) {
  return new SafeHtml(value);
}

function render(value) {
  if (value === null || value === undefined || value === false) return '';
  if (value instanceof SafeHtml) return value.value;
  if (Array.isArray(value)) return value.map(render).join('');
  return escapeHtml(value);
}

/**
 * Tagged template that escapes every interpolation by default.
 *
 * This is the only way templates in this project are built: getting HTML
 * injection wrong requires going out of your way (calling `raw`), rather than
 * being the thing that happens if you forget.
 */
function html(strings, ...values) {
  let output = strings[0];
  for (let i = 0; i < values.length; i += 1) {
    output += render(values[i]) + strings[i + 1];
  }
  return new SafeHtml(output);
}

module.exports = { html, raw, escapeHtml, SafeHtml };
