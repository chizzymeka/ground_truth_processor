import json
import os

from pydriller import Repository

# read file
with open('E:/Year 1 Project Dataset/Ground Truth Data/ground_truth_phase_1.json', 'r') as ground_truth_data_file:
    ground_truth_data_phase_1 = ground_truth_data_file.read()

# parse file
resolution_version_objects = json.loads(ground_truth_data_phase_1)


def get_modified_line_numbers_as_json():

    github_path_prefix = 'https://github.com/apache/tomcat/commit/'
    tomcat_repo = 'https://github.com/apache/tomcat'
    commit_hashes = []

    # Collect GitHub commit hashes.
    for resolution_version_object in resolution_version_objects:
        for resolution_version_value in resolution_version_object:
            cve_id_objects = resolution_version_object[resolution_version_value]
            for cve_id_value in cve_id_objects:
                commits = cve_id_objects[cve_id_value]['vulnerabilityFixLocations']
                for commit_id_value in commits:
                    commit_objects = commits[commit_id_value]
                    for commit_url in commit_objects:
                        if github_path_prefix in commit_url:
                            commit_hash = commit_url.split('https://github.com/apache/tomcat/commit/')[1]
                            commit_hashes.append(commit_hash)

    # Get changed line numbers from each modified source file.
    commit_url_and_file_path_suffix_and_line_numbers = {}

    for commit_hash in commit_hashes:
        # Traverse the collected URLs using PyDriller.
        for commit in Repository(tomcat_repo, single=commit_hash, only_modifications_with_file_types=['.java']).traverse_commits():

            commit_url = github_path_prefix + commit.hash
            # print(commit_url)
            file_path_suffix_and_line_numbers = {}
            for file in commit.modified_files:
                file_path_suffix = file.new_path
                # print(file_path_suffix)

                # diff_parsed contains diff parsed in a dictionary containing the added and deleted lines. The
                # dictionary has 2 keys: “added” and “deleted”, each containing a list of Tuple (int,
                # str) corresponding to (number of line in the file, actual line).
                diff_parsed = file.diff_parsed  # dictionary
                added_code_changes = diff_parsed.get('added')  # list
                deleted_code_changes = diff_parsed.get('deleted')  # list

                line_numbers = []
                # Iterate through tuples holding number of line in the file and the actual line as described above.
                for added_code_change_tuple in added_code_changes:
                    line_number = added_code_change_tuple[0]
                    line_numbers.append(line_number)
                    # print(line_number)

                # Iterate through tuples holding number of line in the file and the actual line as described above.
                for deleted_code_change_tuple in deleted_code_changes:
                    line_number = deleted_code_change_tuple[0]
                    line_numbers.append(line_number)
                    # print(line_number)
                if '.java' in file_path_suffix:
                    file_path_suffix_and_line_numbers[file_path_suffix] = line_numbers
                commit_url_and_file_path_suffix_and_line_numbers[commit_url] = file_path_suffix_and_line_numbers

    with open("commit_url_and_file_path_suffix_and_line_numbers.json", "w") as output_json_file:
        json.dump(commit_url_and_file_path_suffix_and_line_numbers, output_json_file)


def update_ground_truth_json_data():
    # read file
    with open('commit_url_and_file_path_suffix_and_line_numbers.json', 'r') as line_numbers_json_file:
        line_numbers_json_data = line_numbers_json_file.read()

    # parse file
    commit_url_and_file_path_suffix_and_line_numbers = json.loads(line_numbers_json_data)

    ground_truth_phase_2 = resolution_version_objects
    for commit_url_value in commit_url_and_file_path_suffix_and_line_numbers:
        file_path_suffix_and_line_numbers = commit_url_and_file_path_suffix_and_line_numbers[commit_url_value]
        for file_path_suffix_value in file_path_suffix_and_line_numbers:
            line_numbers = file_path_suffix_and_line_numbers[file_path_suffix_value]

            # Set up 'lines' JSON element structure to be inserted into the ground truth JSON file.
            lines = {}
            modification_location_details = {
                'className': '',
                'methodSignature': ''
            }
            for line_number in line_numbers:
                lines[line_number] = modification_location_details
                # Update ground truth data
                for resolution_version_object in ground_truth_phase_2:
                    for resolution_version_value in resolution_version_object:
                        cve_id_objects = resolution_version_object[resolution_version_value]
                        for cve_id_value in cve_id_objects:
                            commits = cve_id_objects[cve_id_value]['vulnerabilityFixLocations']
                            for commit_id_value in commits:
                                commit_objects = commits[commit_id_value]
                                for commit_url in commit_objects:
                                    file_path_suffix_objects = commit_objects[commit_url]
                                    for file_path_suffix in file_path_suffix_objects:
                                        if commit_url_value == commit_url and file_path_suffix_value == file_path_suffix:
                                            # Add the dictionary holding line number and placeholders for class name
                                            # and method signature (see above) to the file path suffix dictionary to
                                            # update the JSON data.
                                            file_path_suffix_objects[file_path_suffix] = lines

    with open("E:/Year 1 Project Dataset/Ground Truth Data/ground_truth_phase_2.json", "w") as output_json_file:
        json.dump(ground_truth_phase_2, output_json_file)


if __name__ == '__main__':

    if not os.path.exists('commit_url_and_file_path_suffix_and_line_numbers.json'):
        get_modified_line_numbers_as_json()
    else:
        update_ground_truth_json_data()
