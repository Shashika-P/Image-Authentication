import convert_image
import image_authentication

print("Welcome to Image Authentication Software")
while True:
    print("1. Convert Image")
    print("2. Authenticate Image")
    print("q. Quit")
    choice = input("Enter your choice: ")

    if choice == '1':
        image_path = input("Enter image path: ")
        convert_image.convert_image(image_path)

    elif choice == '2':
        image_path = input("Enter image path: ")
        image_authentication.image_authentication(image_path)

    elif choice == 'q':
        print('Thank you')
        break
    else:
        print("Invalid choice. Please try again.")