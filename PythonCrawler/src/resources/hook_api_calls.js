const originalHasStorageAccess = document.hasStorageAccess;
const originalRequestStorageAccess = document.requestStorageAccess;
const originalRequestStorageAccessFor = document.requestStorageAccessFor;

document.hasStorageAccess = async function() {
    try {
        console.log(await navigator.permissions.query({"name": "storage-access"}));
    } catch (error) {
        console.log("Permissions API not supported")
    }
    const result = await originalHasStorageAccess.apply(this, arguments);
    window.sa_call_handler("hasStorageAccess", result)
    return result;
};

document.requestStorageAccess = function() {
    const result = originalRequestStorageAccess.apply(this, arguments);
    window.sa_call_handler("requestStorageAccess", "None")
    return result;
};

document.requestStorageAccessFor = function() {
    const result = originalRequestStorageAccessFor.apply(this, arguments);
    window.sa_call_handler("requestStorageAccessFor", "None")
    return result;
};
