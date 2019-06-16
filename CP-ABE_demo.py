from charm.toolbox.pairinggroup import PairingGroup, GT
from bsw07 import BSW07
from io import open



def main():
    # instantiate a bilinear pairing map
    # 'MNT224' represents an asymmetric curve with 224-bit base field
    pairing_group = PairingGroup('MNT224')
    
    #CP-ABE under DLIN (2-linear)
    cpabe = BSW07(pairing_group, 2)


    #Ask for customer's details to generate the key
    print("Please let us have your details")
    print("================================")
    First_name = input("First Name:  ")

    surname = input("Surname:  ")

    cus_id = First_name + ' ' + surname

    print()
    
    #Run the set up
    (pk, msk) = cpabe.setup()

    print("Master key generated for all access to transaction file")
    print("Public key for,", cus_id + ' ' + "generated")
    
    print()
    print("Please choose which describes you")
    print("=================================")
    print()
    print("1. Single User License, Location: Edinburgh | 2. Multiple User License, Location: Edinburgh | 3. Other Users License, Location: London")
    cus_type = input("Your option (1, 2 or 3) :  ")
    
    #Initialising the options
    while (cus_type != ' '):
        if cus_type == "1":
            cus_1_type_attr_list = ['SINGLE-USER-LICENSE', 'LOCATION-EDINBURGH']
            cus_1_type_key = cpabe.keygen(pk, msk, cus_1_type_attr_list)

            #Read customer's file
            print(" ")
            print("......reading transaction file")
            print()

            #Choose a random message in place of customer's file
            msg = pairing_group.random(GT)
            print("File read and converted into a pairing element")
            print()

            #Generate a ciphertext
            print("Encrypting transaction file for customers with access policy embedded in it.")
            print()
            print("Setting the policy for acccess to the transation file.")
            policy_str = '((SINGLE-USER-LICENSE and LOCATION-EDINBURGH) or (MULTIPLE-USER-LICENSE and EDINBURGH))'

            print("Done...")
            print()
            print("Encrypting transaction file with ", cus_id + 's' + ' ' + "public key in progress.")
            cipher_text = cpabe.encrypt(pk, msg, policy_str)

            print()
            print("File encrypted and stored in memory for customers to access when needed.")

            print()
            print("Using ", cus_id + 's' + ' ' + "private key to decrypt the transaction file in progress")
            
            #Decryption as Single User License Holder
            print()
            print("Decryption for ", cus_id + ' ' + "as sinlge user license holder in progress.")
            print()

            rec_msg = cpabe.decrypt(pk, cipher_text, cus_1_type_key)

            print()

            if rec_msg == msg:
                print ("Successful decryption for, ", cus_id + ' ' + "as a single user license holder.")
                print("Congratulations!!!")
            else:
                print ("Decryption for ", cus_id + ' ' + "as a single user license holder failed.")
                
            break

        elif cus_type == "2":
            cus_2_type_attr_list = ['MULTIPLE-USER-LICENSE', 'LOCATION-EDINBURGH']
            cus_2_type_key = cpabe.keygen(pk, msk, cus_2_type_attr_list)

            #Read customer's file
            print(" ")
            print("......reading transaction file")
            print()

            #Choose a random message in place of customer's file
            msg_2 = pairing_group.random(GT)
            print("File read and converted into a pairing element")
            print()
        
            #Generate a ciphertext
            print("Encrypting transaction file for customers with access policy embedded in it.")

            print()
            print("Setting the policy for acccess to the transation file")
            policy_str = '((SINGLE-USER-LICENSE and LOCATION-EDINBURGH) or (MULTIPLE-USER-LICENSE and LOCATION-EDINBURGH))'

            print("Done...")
            print()
            print("Encrypting transaction file with ", cus_id + 's' + ' ' +"public key")
            cipher_text = cpabe.encrypt(pk, msg_2, policy_str)

            print()
            print("File encrypted and stored in memory for customers to access when needed.")

            print()
            print("Using ", cus_id + 's' + ' ' + "private key to decrypt the transaction file in progress")
            
            #Decryption as a multiple user license holder
            print()
            print("Decryption for ", cus_id +' ' + "as a multiple user license holder in progress.")
            print()

            rec_msg_2 = cpabe.decrypt(pk, cipher_text, cus_2_type_key)
            print()

            if rec_msg_2 == msg_2:
                print ("Successful decryption for ", cus_id + ' ' + "as a multiple user license.")
                print("Congratulations!!!")
                      
            else:
                print ("Decryption for ", cus_id + ' ' + "as a multiple user license failed.")
            break


        elif cus_type == "3":
            cus_3_type_attr_list = ['OTHER-USERS-LICENSE', 'LOCATION-EDINBURGH']
            cus_3_type_key = cpabe.keygen(pk, msk, cus_3_type_attr_list)

            #Read customer's file
            print(" ")
            print("......reading transaction file")
            print()
                      
            #Choose a random message in place of customer's file
            msg_3 = pairing_group.random(GT)

            print("File read and converted into a pairing element")

            print()
            
            #Generate a ciphertext
            print("Encrypting transaction file for customers with access policy embedded in it.")

            print()
            print("Setting the policy for acccess to the transation file")
            policy_str = '((SINGLE-USER-LICENSE and LOCATION-EDINBURGH) or (MULTIPLE-USER-LICENSE and LOCATION-EDINBURGH))'

            print("Done...")
            print()
            print("Encrypting transaction file with ", cus_id + 's' + ' ' +"public key")
            cipher_text = cpabe.encrypt(pk, msg_3, policy_str)

            print()
            print("File encrypted and stored in memory for customers to access when needed.")

            print()
            print("Using ", cus_id + 's' + ' ' + "private key to decrypt the transaction file in progress.")
                        
            #Decryption as other users license holder
            print()
            print("Decryption for ", cus_id + ' ' + "as other users license holder in progress.")

            rec_msg_3 = cpabe.decrypt(pk, cipher_text, cus_3_type_key)
            if rec_msg_3 == msg_3:
                print ("Successful decryption for ", cus_id + ' ' + "as a other users license holder.")
                print("Congratulations!!!")
                      
            else:
                print ("Decryption for ", cus_id +' ' + "as a other users license holder failed.")
            break
            
        else:
            print("Check your back your input and try again")
            break
        

if __name__ == "__main__":
    main()
