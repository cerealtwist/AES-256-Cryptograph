import os

def create_dummy_csv(filename="test_dataset.csv", folder="output_files"):
    if not os.path.exists(folder):
        print(f"[SETUP] Folder '{folder}' not found. Creating new folder...")
        os.makedirs(folder)

    # Merge folder name and file name (ex. output_files/test_dataset.csv)
    full_path = os.path.join(folder, filename)

    if not os.path.exists(full_path):
        print(f"[SETUP] Generating dummy file '{full_path}' di {os.getcwd()}...")
        with open(full_path, "w") as f:
            f.write("ID,Name,GPA,Subject\n")
            f.write("101,Faiz,3.5,Data Science\n")
            f.write("102,Gres,3.8,Informatika\n")
            f.write("103,Haikal,3.2,Sistem Informasi")
    return full_path