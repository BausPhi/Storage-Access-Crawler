const originalHasStorageAccess = document.hasStorageAccess;
const originalRequestStorageAccess = document.requestStorageAccess;
const originalRequestStorageAccessFor = document.requestStorageAccessFor;
console.log("Test")

document.hasStorageAccess = async function() {
    const result = await originalHasStorageAccess.apply(this, arguments);
    window.sa_call_handler("hasStorageAccess", window.location.href);
    return result;
};

document.requestStorageAccess = function() {
    const result = originalRequestStorageAccess.apply(this, arguments);
    window.sa_call_handler("requestStorageAccess", window.location.href);
    return result;
};

document.requestStorageAccessFor = function() {
    const result = originalRequestStorageAccessFor.apply(this, arguments);
    window.sa_call_handler("requestStorageAccessFor", window.location.href);
    return result;
};
