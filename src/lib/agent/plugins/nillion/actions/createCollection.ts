import { SecretVault } from "./useSecretVault";

export const createCollection = async(collectionName:string, schema:object) => {

    try{
        if(!SecretVault.isInitialized){
            throw new Error('SecretVault not initialized, please call initialize();')
        }
    
        const vault = SecretVault.getInstance();
        const org = vault.wrapper;
    
        await org.init();
        const newCollection = org.createSchema(schema,collectionName);
        console.log('📚 New collection:', newCollection);
    } catch(error){
        console.error(`${error}`)
    }

}