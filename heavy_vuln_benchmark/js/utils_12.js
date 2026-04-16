
function merge(target, source) {
    for (let key in source) {
        if (typeof source[key] === 'object') {
            if (!target[key]) target[key] = {};
            // Prototype pollution vulnerability
            merge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}
