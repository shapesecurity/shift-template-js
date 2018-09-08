// NB: you will need to `npm install --no-save shift-codegen` before running this file.

'use strict';

let Shift = require('shift-ast/checked');
let { default: codeGen, FormattedCodeGen } = require('shift-codegen');

let { applyTemplate } = require('.');


let nameTemplate = ' /*# access # StaticMemberAssignmentTarget #*/this.foo = (/*# access # StaticMemberExpression #*/ this.foo).bind(this);';

function bindClassMethods(klass) {
  // It would not be hard to handle these cases; I'm just really lazy
  if (klass.super !== null) {
    throw new TypeError('Unimplemented: classes with super');
  }
  if (klass.elements.some(e => !e.isStatic && e.method.name.type === 'StaticPropertyName' && e.method.name.value === 'constructor')) {
    throw new TypeError('Unimplemented: classes with constructors');
  }
  let boundNames = klass.elements
    .filter(e => !e.isStatic && e.method.type === 'Method' && e.method.name.type === 'StaticPropertyName' && e.method.name.value !== 'constructor')
    .map(e => e.method.name.value);
  let newCtor = new Shift.ClassElement({
    isStatic: false,
    method: new Shift.Method({
      isGenerator: false,
      name: new Shift.StaticPropertyName({ value: 'constructor' }),
      params: new Shift.FormalParameters({ items: [], rest: null }),
      body: new Shift.FunctionBody({
        directives: [],
        statements: boundNames.map(name => applyTemplate(nameTemplate, { access: ({ type, object }) => new Shift[type]({ object, property: name }) }).statements[0]),
      }),
    }),
  });
  return new Shift[klass.type]({ name: klass.name, super: klass.super, elements: [newCtor].concat(klass.elements) });
}

function matchClassDecorator(text) {
  let match = text.match(/ *(@\w+) */);
  if (match === null) {
    return null;
  }
  return { name: match[1], predicate: node => node.type === 'ClassExpression' || node.type === 'ClassDeclaration' };
}


let example = `

/* @autobind */
class A {
  onclick() {
    console.log(this);
  }

  trigger() {
    this.onclick();
  }
}

/* @autobind */
class B {
  bar() {
    console.log(this);
  }
}

`;


let replaced = applyTemplate(example, { '@autobind': bindClassMethods }, { matcher: matchClassDecorator });

console.log(codeGen(replaced, new FormattedCodeGen));


/*
Output:

```js
class A {
  constructor() {
    this.onclick = this.onclick.bind(this);
    this.trigger = this.trigger.bind(this);
  }
  onclick() {
    console.log(this);
  }
  trigger() {
    this.onclick();
  }
}
class B {
  constructor() {
    this.bar = this.bar.bind(this);
  }
  bar() {
    console.log(this);
  }
}
```

*/
