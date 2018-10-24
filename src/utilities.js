'use strict';

let spec = require('shift-spec').default;

// TODO consider splitting these and the utilities from https://github.com/shapesecurity/shift-reducer-js/blob/es2016/scripts/lib/utilities.js into their own project
function isNodeOrUnionOfNodes(type) {
  return type.typeName === 'Union' && type.arguments.every(isNodeOrUnionOfNodes) || spec.hasOwnProperty(type.typeName);
}

function isStatefulType(type) {
  switch (type.typeName) {
    case 'Enum':
    case 'String':
    case 'Number':
    case 'Boolean':
      return false;
    case 'Maybe':
    case 'List':
      return isStatefulType(type.argument);
    case 'Union':
      return type.arguments.some(isStatefulType);
    default:
      if (isNodeOrUnionOfNodes(type)) {
        return true;
      }
      throw new Error('unimplemented: type ' + type);
  }
}

module.exports = {
  isNodeOrUnionOfNodes,
  isStatefulType,
};
