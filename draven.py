# Copyright (c) Draven (draven.net)
# See the file 'LICENSE' for copying permission
# CREATOR PHARMYX MADE IN 2025
# ----------------------------------------------------------------------------------------------------------------------------------------------------------|
# EN:
#     - Do not touch or modify the code below. If there is an error, please contact the owner, but under no circumstances should you touch the code.
#     - Do not resell this tool, do not credit it to yours.

# DRAVEN TOOL is currently in beta testing, any bugs/errors you find please contact the owner


import os
import requests

version = "v1.0 - BETA"
author = "Pharmyx"
contact = "pharmyx"
divider = "========================================"

# Main intro function
def draven():
    print("""
██████╗ ██████╗  █████╗ ██╗   ██╗███████╗███╗   ██╗
██╔══██╗██╔══██╗██╔══██╗██║   ██║██╔════╝████╗  ██║
██║  ██║██████╔╝███████║██║   ██║█████╗  ██╔██╗ ██║
██║  ██║██╔══██╗██╔══██║╚██╗ ██╔╝██╔══╝  ██║╚██╗██║
██████╔╝██║  ██║██║  ██║ ╚████╔╝ ███████╗██║ ╚████║
╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═══╝
    """)
    print("Draven is a tool made by Pharmyx for testing and securing your own devices. \nIt’s meant to be used responsibly. Using it to harm others or break into systems you don’t own is illegal. \nIf you get caught misusing it, you could face serious consequences, like arrest.")

# IP Tracker function
def track_ip():
    ip = input("Enter the IP address you want to track: ")
    try:
        # Using ip-api.com for free geolocation data  find a more advanced one later
        response = requests.get(f"http://ip-api.com/json/{ip}")
        data = response.json()

        if data["status"] == "success":
            print("\nIP Tracking Results:")
            print(f"IP Address: {data['query']}")
            print(f"Country: {data['country']} ({data['countryCode']})")
            print(f"Region: {data['regionName']}")
            print(f"City: {data['city']}")
            print(f"ZIP Code: {data['zip']}")
            print(f"Latitude: {data['lat']}")
            print(f"Longitude: {data['lon']}")
            print(f"ISP: {data['isp']}")
        else:
            print("Error: Could not retrieve data for this IP. It might be invalid or private.")
    except Exception as e:
        print(f"An error occurred: {e}")
    input("\nPress Enter to return to the menu...")

# Clear screen function
def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

# Main menu function
def main_menu():
    while True:
        clear_screen()
        draven()
        print(divider)
        print("\nMain Menu:")
        print("1. INFO")
        print("2. WEBSITE")
        print("3. CONTACT")
        print("4. Exit")
        print("\nOSINT-Tools:")
        print("5. IP Logger")
        print("6. IP Tracker")
        print("\nDiscord Tools:")
        print("7. Discord Bot Server Nuker")
        print("8. Discord Spammer")

        choice = input("\nEnter your choice (1-5): ")

        if choice == "1":
            clear_screen()
            draven()
            print(divider)
            print(f"Draven {version} by {author} - A tool for ethical hacking and testing.")
            input("\nPress Enter to return to the menu...")
        elif choice == "2":
            clear_screen()
            draven()
            print(divider)
            print("Website feature not implemented yet.")
            input("\nPress Enter to return to the menu...")
        elif choice == "3":
            clear_screen()
            draven()
            print(divider)
            print(f"Contact me on discord {contact}")
            input("\nPress Enter to return to the menu...")
        elif choice == "4":
            clear_screen()
            draven()
            print(divider)
            print("Exiting Draven.")
            break
        elif choice == "5":
            clear_screen()
            draven()
            print(divider)
            print("IP Logger feature not implemented yet.")
            input("\nPress Enter to return to the menu...")
        elif choice == "6":
            clear_screen()
            draven()
            print(divider)
            track_ip()
        elif choice == "7":
            clear_screen()
            draven()
            print(divider)
            print("Discord feature not implemented yet.")
            input("\nPress Enter to return to the menu...")
        elif choice == "8":
            clear_screen()
            draven()
            print(divider)
            print("Discord feature not implemented yet.")
            input("\nPress Enter to return to the menu...")
        else:
            clear_screen()
            draven()
            print(divider)
            print("Invalid choice. Please enter a number between 1 and 5.")
            input("\nPress Enter to return to the menu...")

# Initial run
main_menu()