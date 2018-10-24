'use strict';

const findNodes = require('./src/find-nodes.js');
const applyTemplate = require('./src/apply-template.js');
const applyStructuredTemplate = require('./src/apply-structured-template.js');
const replace = require('./src/replace.js');

module.exports = { findNodes, replace, applyTemplate, applyStructuredTemplate };
