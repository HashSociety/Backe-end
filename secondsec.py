import pandas as pd
import io

def load_first_section_of_csv(file_path):
    # Initialize variables to store the content of the first section
    first_section = ""

    with open(file_path, 'r') as file:
        # Read the entire file content as a string
        content = file.read()

        # Find the index of the blank row that separates the two sections of headers
        blank_row_index = content.find('\n\n')

        # Separate the content into the first section
        first_section = content[:blank_row_index]

    # Load the first section using pandas
    df = pd.read_csv(io.StringIO(first_section))

    return df

def load_second_section_of_csv(file_path):
    # Initialize variables to store the content of the second section
    second_section = ""

    with open(file_path, 'r') as file:
        # Read the entire file content as a string
        content = file.read()

        # Find the index of the blank row that separates the two sections of headers
        blank_row_index = content.find('\n\n')

        # Separate the content into the second section
        second_section = content[blank_row_index+2:]  # +2 to skip the blank row

    # Load the second section using pandas
    df = pd.read_csv(io.StringIO(second_section))

    return df

# Example usage
file_path = 'capture.pcapng-01.csv'
first_section_df = load_first_section_of_csv(file_path)
print(first_section_df)
second_section_df = load_second_section_of_csv(file_path)
