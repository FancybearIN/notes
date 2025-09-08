Prototype pollution is a JavaScript vulnerability that enables an attacker to add arbitrary properties to global object prototypes, which may then be inherited by user-defined objects

## What is an object in JavaScript?

A JavaScript object is essentially just a collection of `key:value` pairs known as "properties".

## What is a prototype in JavaScript?

Every object in JavaScript is linked to another object of some kind, known as its prototype. By default, JavaScript automatically assigns new objects one of its built-in prototypes

`let myObject = {}; Object.getPrototypeOf(myObject); // Object.prototype let myString = ""; Object.getPrototypeOf(myString); // String.prototype let myArray = []; Object.getPrototypeOf(myArray); // Array.prototype let myNumber = 1; Object.getPrototypeOf(myNumber); // Number.prototype

## How does object inheritance work in JavaScript?

Whenever you reference a property of an object, the JavaScript engine first tries to access this directly on the object itself. If the object doesn't have a matching property, the JavaScript engine looks for it on the object's prototype instead. Given the following objects, this enables you to reference `myObject.propertyA`,


exitingobject
	properties a
	 propertie b
is protoype

myobject
	propertyc

## The prototype chain

Note that an object's prototype is just another object, which should also have its own prototype, and so on. As virtually everything in JavaScript is an object under the hood, this chain ultimately leads back to the top-level `Object.prototype`, whose prototype is simply `null`.

![JavaScript prototype chain](https://portswigger.net/web-security/prototype-pollution/images/prototype-pollution-prototype-chain.svg)

Crucially, objects inherit properties not just from their immediate prototype, but from all objects above them in the prototype chain. In the example above, this means that the `username` object has access to the properties and methods of both `String.prototype` and `Object.prototype`.


## Accessing an object's prototype using __proto__

Every object has a special property that you can use to access its prototype. Although this doesn't have a formally standardized name, `__proto__` is the de facto standard used by most browsers. If you're familiar with object-oriented languages, this property serves as both a getter and setter for the object's prototype. This means you can use it to read the prototype and its properties, and even reassign them if necessary.

As with any property, you can access `__proto__` using either bracket or dot notation:

`username.__proto__ username['__proto__']`

You can even chain references to `__proto__` to work your way up the prototype chain:
**DOM Invader**
`username.__proto__ // String.prototype username.__proto__.__proto__ // Object.prototype username.__proto__.__proto__.__proto_`

## Prototype pollution sinks

A prototype pollution sink is essentially just a JavaScript function or DOM element that you're able to access via prototype pollution, which enables you to execute arbitrary JavaScript or system commands. We've covered some client-side sinks extensively in our topic on DOM XSS.

## Finding client-side prototype pollution sources manually

Finding prototype pollution sources manually is largely a case of trial and error. In short, you need to try different ways of adding an arbitrary property to `Object.prototype` until you find a source that works


[Study resources]()