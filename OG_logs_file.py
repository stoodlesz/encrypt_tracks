'''FleaLogs file provides the logs function and the chocie menu
to select or quit the logs'''
import logging
# This library imports the logging function which provides the application.
# log file to be used to track any attempt of the user
# Configures logging function which helps to see the logs.
# It includes the filename= filename to where the logs will be stored,
# the level= sets the root logger level to handle/
# print all the messages of severity INFO or higher
# Additionally, there are warning messages that are also handled
# using logging.warning.
# Additionally, the format specifys the layout of the message
# of one time log per message
# (including time of created logmessage,
# the level of log message and the message) seperated my comma.
# Finally the dategfmt provides the format of date and time using
# the american format:
# Year-Month-Day Hour:Minute:Second.
logging.basicConfig(filename='application.log', level=logging.INFO,
                    format='%(asctime)s %(levelname)s: %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')


class AdminTools:
    ''' This AdminTools class provides a choice menu that allows the user
    to navigate between
    two options the logs file and the back menu'''

    def choice_logs_menu(self):
        '''This method provides a selection menu to access the
        logs or go back to the main menu'''
        while True:
            print("\n Admin tools Menu:")
            print("[1] option 1: Select 1 for logs")
            print("[2] option 2: Select 2 to quit")

            choice = input("> ")

            if choice == "1":
                logging.info("Admin user accessed the logs.")
                print("Logs file has been opened.")
                self.logs()
            elif choice == "2":
                logging.info("Admin user chose to go back to the main menu.")
                print("Returning to the main menu.")
                break
            else:
                print("Invalid choice. Please enter 1, 2")

    def logs(self):
        '''creates and opens the application.log file and then reads
         all the avaliable activities logged
         with the logging.info and logging.warning'''
        logs_file = "application.log"
        try:
            with open(logs_file, "r", encoding='utf-8') as file:
                logs_messages = file.read()
                print(logs_messages)
        except FileNotFoundError:
            print("Logs file failed to open.")
