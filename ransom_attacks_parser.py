import ijson
import psycopg2
from db_connection import create_connection, set_schema

def parse_ransomware_data(filename):
    try:
        # Establish the connection
        connection = create_connection()
        if connection is None:
            print("DB connection not available")
            return

        # Open cursor to DB
        cursor = connection.cursor()

        # Set the search path to the specific schema
        set_schema(cursor, 'attacks_repo')


        with open(filename, 'r') as f:
            # Create an iterator to parse the JSON file incrementally
            parser = ijson.items(f, 'item')

            count = 0
            error_count = 0
            # Iterate over each object in the JSON array
            for obj in parser:
                try:
                    count += 1

                    # Ransomeware attack name
                    name = None if 'name' not in obj or len(obj['name']) == 0 else obj['name'][0]

                    if name is not None:
                        # Begin the transaction
                        cursor.execute("BEGIN;")

                        # Extract information about the attack. 
                        decryptor = "" if 'decryptor' not in obj else obj['decryptor']
                        screenshots = "" if 'screenshots' not in obj else obj['screenshots']
                        ms_detection = "" if 'microsoftDetectionName' not in obj else obj['microsoftDetectionName']
                        ms_info = "" if 'microsoftInfo' not in obj else obj['microsoftInfo']
                        sandbox = "" if 'sandbox' not in obj else obj['sandbox']
                        iocs = "" if 'iocs' not in obj else obj['iocs']
                        snort = "" if 'snort' not in obj else obj['snort']
                        
                        # Split if the names if there is a new line character (Data quality)
                        unquie_name = name.split("\n")
                        cursor.execute("""
                            INSERT INTO ransomware (name, decryptor, screenshots, ms_detection, ms_info, sandbox, snort)
                            VALUES (%s, %s, %s, %s, %s, %s, %s)
                            RETURNING uid
                        """, (unquie_name[0], decryptor, screenshots, ms_detection, ms_info, sandbox, snort))

                        # Fetch the generated uid
                        uid = cursor.fetchone()[0]

                        # Alias
                        for _name in unquie_name[1:]:
                            cursor.execute("""
                                INSERT INTO ransomware_alias (parent_id, alias)
                                VALUES (%s, %s)
                            """, (uid, _name))

                        for name in obj['name'][1:]:
                            for _name in name.split("\n"):
                                cursor.execute("""
                                    INSERT INTO ransomware_alias (parent_id, alias)
                                    VALUES (%s, %s)
                                """, (uid, _name))

                        # Resources
                        if 'resources' in obj:
                            for resources in obj['resources']:
                                cursor.execute("""
                                    INSERT INTO ransomware_resources (parent_id, resources)
                                    VALUES (%s, %s)
                                """, (uid, resources))

                        # Extensions
                        extensions = None if 'extensions' not in obj else obj['extensions']
                        if extensions is not None:
                            for ext in extensions.split("\n"):
                                cursor.execute("""
                                    INSERT INTO ransomware_ext (parent_id, ext)
                                    VALUES (%s, %s)
                                """, (uid, ext))

                        # Extension Pattern
                        extensionPattern = None if 'extensionPattern' not in obj else obj['extensionPattern']
                        if extensionPattern is not None:
                            for ext_patern in extensionPattern.split("\n"):
                                cursor.execute("""
                                    INSERT INTO ransomware_ext_pattern (parent_id, ext_pattern)
                                    VALUES (%s, %s)
                                """, (uid, ext_patern))

                        # Notes
                        ransomNoteFilenames = None if 'ransomNoteFilenames' not in obj else obj['ransomNoteFilenames']
                        if ransomNoteFilenames is not None:
                            for notes in ransomNoteFilenames.split("\n"):
                                cursor.execute("""
                                    INSERT INTO ransomware_notes (parent_id, notes)
                                    VALUES (%s, %s)
                                """, (uid, notes))

                        # Comments
                        comment = None if 'comment' not in obj else obj['comment']
                        if comment is not None:
                            for comm in comment.split("\n"):
                                cursor.execute("""
                                    INSERT INTO ransomware_comments (parent_id, comments)
                                    VALUES (%s, %s)
                                """, (uid, comm))

                        # Algo
                        encryptionAlgorithm = None if 'encryptionAlgorithm' not in obj else obj['encryptionAlgorithm']
                        if encryptionAlgorithm is not None:
                            for algo in encryptionAlgorithm.split("\n"):
                                cursor.execute("""
                                    INSERT INTO ransomware_algo (parent_id, algo)
                                    VALUES (%s, %s)
                                """, (uid, algo))

                        # Commit the transaction
                        connection.commit()
                        print(f"Record inserted successfully for {unquie_name[0]}")       
                    else:
                        print(f"Item at: {count} is None")
                except (Exception, psycopg2.Error) as error:
                    # Rollback the transaction in case of error
                    error_count += 1 
                    print("Error while creating a record for: ", error)
                    connection.rollback()
            print(f"Total items parsed: {count} Errors: {error_count}")    
    except (Exception) as error:
        print("Error while creating a record: ", error)
    finally:
        # Close the cursor and connection
        if connection:
            cursor.close()
            connection.close()
            print("PostgreSQL connection is closed")

if __name__ == "__main__":
    parse_ransomware_data("ransomware_overview.json")
