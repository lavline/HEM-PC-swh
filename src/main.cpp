#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <time.h>
#include "HEMBS.h"
#include "read.h"
#include "random.h"

using namespace std;

double get_nano_time(struct timespec* a, struct timespec* b) {
	return (b->tv_sec - a->tv_sec) * 1000000000 + b->tv_nsec - a->tv_nsec;
}

int main(int argc, char* argv[]) {
	ACL_rules* acl_rules = new ACL_rules;
	ACL_messages* messages = new ACL_messages;

	bool enable_log = false;
	bool enable_update = false;
	int log_level = 1; // {1,2,3}
	struct timespec t1, t2;

	if (argc == 1) { fprintf(stderr, "use -h(--help) to print the usage guideline.\n"); return 0; }
	int opt;
	struct option opts[] = {
		{"ruleset", 1, NULL, 'r'},
		{"packet", 1, NULL, 'p'},
		{"log", 1, NULL, 'l'},
		{"update", 0, NULL, 'u'},
		{"help", 0, NULL, 'h'},
		{0, 0, 0, 0}
	};

	while ((opt = getopt_long(argc, argv, "r:p:l:uh", opts, NULL)) != -1) {
		switch (opt)
		{
		case 'r':
			read_rules_cbFormat(optarg, acl_rules);
			printf("read rules file (%s %d)\n", optarg, acl_rules->size);
			break;
		case 'p':
			read_messages_cbFormat(optarg, messages);
			printf("read_messages (%s %d)\n", optarg, messages->size);
			break;
		case 'f': {
			// set layer
			break;
		}
		case 'l':
			enable_log = true;
			log_level = atoi(optarg);
			if (log_level < 1 || log_level>3) {
				fprintf(stderr, "error-unknown log level %d.\n", log_level);
				return -1;
			}
			cout << "Enable log:    level " << log_level << endl;
			break;
		case 'u':
			enable_update = true;
			cout << "Enable update\n";
			break;
		case 'h':
			cout << "\n************************************************************************************************************************************************************\n";
			cout << "* -r(--ruleset): Input the rule set file. This argument must be specified. (Example: [-r acl1])                                                            *\n";
			cout << "* -p(--packet):  Input the packet set file. If not set, the program will generate randomly. (Example: [-p acl1_trace])                                     *\n";
			cout << "* -l(--log):     Enable the log. Have three level 1-3. (Example: [-l 3])                                                                                   *\n";
			cout << "* -u(--update):  Enable update. (Example: [-u])                                                                                                            *\n";
			cout << "* -h(--help):    Print the usage guideline.                                                                                                                *\n";
			cout << "************************************************************************************************************************************************************\n\n";
			if (argc == 1)return 0;
			break;
		case '?':
			fprintf(stderr, "error-unknown argument -%c.", optopt);
			return -1;
		default:
			break;
		}
	}

	double totalConstructionTimeMs = 0.0;
	double totalAvgSearchTimeUs = 0.0;
	double totalAvgUpdateTimeUs = 0.0;
	double totalAvgMemorySizeB = 0.0;
	double totalAvgCheckNum = 0;
	double totalAvgANDNum = 0;
	double totalAvgCMPNum = 0;
	double totalAvgAggBingoNum = 0;
	double totalAvgAggFailNum = 0;
	uint64_t totalRules = 0;
	uint64_t totalMessages = 0;

	const string file_path = "HEM_AFBS.txt";
	string content;

	//for (int dno = 0; dno < numDataSets; dno++)
	//{	

	totalRules += acl_rules->size;
	totalMessages += messages->size;

	clock_t clk = clock();
	HEMBS hem_afbs;
	hem_afbs.aggregate_forward_init_bitsets_IPv4(acl_rules->size);

	for (int i = 0; i < acl_rules->size; i++)
		hem_afbs.aggregate_forward_bitsets_insert_IPv4(acl_rules->list + i);

	double constructionTimeMs = (double)(clock() - clk) * 1000.0 / CLOCKS_PER_SEC;
	totalConstructionTimeMs += constructionTimeMs;
	totalAvgMemorySizeB += hem_afbs.calMemory() / acl_rules->size;

	uint32_t ruleNo;
	uint64_t checkNum = 0, and64Num = 0, cmpNum = 0, aggBingo = 0, aggFail = 0;
	//clk = clock();

	double search_time = 0;
	clock_gettime(CLOCK_REALTIME, &t1);
	for (int i = 0; i < messages->size; i++)
	{
#if DEBUG
		std::array<uint64_t, 5> debugInfo = hem_afbs.aggregate_forward_bitsets_search_IPv4(
			messages->list + i, acl_rules->list, ruleNo);
		checkNum += debugInfo[0];
		and64Num += debugInfo.at(1);
		cmpNum += debugInfo[2];
		aggBingo += debugInfo[3];
		aggFail += debugInfo[4];
#else
		hem_afbs.aggregate_forward_bitsets_search_IPv4(messages->list + i, acl_rules->list, ruleNo);
#endif
#if VERIFICATION
		
#endif
	}
	clock_gettime(CLOCK_REALTIME, &t2);
	search_time = get_nano_time(&t1, &t2);
	//double avgSearchTimeUs = (double)(clock() - clk) * 1000000.0 / CLOCKS_PER_SEC / messages->size;
	double avgSearchTimeUs = search_time / messages->size / 1000.0;
	totalAvgSearchTimeUs += avgSearchTimeUs;
	double avgCheckNum = (double)checkNum / messages->size;
	totalAvgCheckNum += avgCheckNum;
	double avgANDNum = (double)and64Num / messages->size;
	totalAvgANDNum += avgANDNum;
	double avgCMPNum = (double)cmpNum / messages->size;
	totalAvgCMPNum += avgCMPNum;
	double avgAggBingoNum = (double)aggBingo / messages->size;
	totalAvgAggBingoNum += avgAggBingoNum;
	double avgAggFailNum = (double)aggFail / messages->size;
	totalAvgAggFailNum += avgAggFailNum;

	int rand_update[acl_rules->size];
	RandomGenerator rg;
	for (int ra = 0; ra < acl_rules->size; ra++) { //1000000
		rand_update[ra] = rg.rand_int(2); //0:insert 1:delete
	}
	clk = clock();
	for (int ra = 0; ra < acl_rules->size; ra++) {
		if (rand_update[ra] == 0) { //0:insert
			hem_afbs.aggregate_forward_bitsets_insert_IPv4(acl_rules->list + ra);
		}
		else {//1:delete
			hem_afbs.aggregate_forward_bitsets_delete_IPv4(acl_rules->list + ra);
		}
	}
	double avgUpdateTimeUs = (double)(clock() - clk) * 1000000.0 / CLOCKS_PER_SEC / acl_rules->size;
	totalAvgUpdateTimeUs += avgUpdateTimeUs;

	printf("HEM-AFBS-a%d-CW%d-k%d : constructionTime= %.3f ms, searchTime= %.3f us, updateTime= %.3f us\n"
		"memorySize= %.3f MB, avgMemorySize= %.3f B/', avgCheckNum= %.3f, avgANDNum= %.3f, avgCMPNum= %.3f\n"
		"avgAggBingo= %.3f, avgAggFail= %.3f\n\n", \
		HEM_BS_NUM_ATTR, HEM_BS_PORT_CELLWIDTH, AGGREGATE_RATIO, \
		constructionTimeMs, avgSearchTimeUs, avgUpdateTimeUs, \
		hem_afbs.calMemory() / 1024.0 / 1024.0, hem_afbs.calMemory() / acl_rules->size,
		avgCheckNum, avgANDNum, avgCMPNum, avgAggBingoNum, avgAggFailNum);

		/*content += expID + "-d" + to_string(dno + 1) \
			+ ": search= " + Utils::Double2String(avgSearchTimeUs)\
			+ " us update= " + Utils::Double2String(avgUpdateTimeUs)\
			+ " us construct= " + Utils::Double2String(constructionTimeMs)\
			+ " ms memory= " + Utils::Double2String(hem_afbs.calMemory() / 1024.0 / 1024.0) \
			+ " MB check= " + Utils::Double2String(avgCheckNum) + " and= " + Utils::Double2String(avgANDNum) \
			+ " cmp= " + Utils::Double2String(avgCMPNum) \
			+ " bingo= " + Utils::Double2String(avgAggBingoNum)\
			+ " fail= " + Utils::Double2String(avgAggFailNum) + "\n";*/
	//}

	/*printf("\nExp%s HEM-AFBS-k%d-a%d: constructTime= %.3f ms, updateTime= %.3f us, searchTime= %.3f us\n"
		"checkNum= %.3f, and64Num= %.3f, cmpNum= %.3f, bingo= %.3f, fail= %.3f\n"
		"memorySize= %.3f B/' ruleNum= %lu, msgNum= %lu\n\n\n\n", \
		expID.c_str(), AGGREGATE_RATIO, HEM_BS_NUM_ATTR,
		totalConstructionTimeMs / numDataSets, totalAvgUpdateTimeUs / numDataSets,
		totalAvgSearchTimeUs / numDataSets, totalAvgCheckNum / numDataSets,
		totalAvgANDNum / numDataSets, totalAvgCMPNum / numDataSets, \
		totalAvgAggBingoNum / numDataSets, totalAvgAggFailNum / numDataSets, \
		totalAvgMemorySizeB / numDataSets, totalRules, totalMessages);*/
#if DEBUG
	content += "DEBUG";
#endif
	/*content += "Exp" + expID + "-a" + to_string(HEM_BS_NUM_ATTR) + "-D" + to_string(DATASET_NO) + "-S"
		+ to_string(SHUFFLEMESSAGES) + "-CW" + to_string(HEM_BS_PORT_CELLWIDTH) + "-k" + to_string(AGGREGATE_RATIO)\
		+ " AVG: S= " + Utils::Double2String(totalAvgSearchTimeUs / numDataSets)\
		+ " us Udt= " + Utils::Double2String(totalAvgUpdateTimeUs / numDataSets)\
		+ " us CST= " + Utils::Double2String(totalConstructionTimeMs / numDataSets)\
		+ " ms M= " + Utils::Double2String(totalAvgMemorySizeB / numDataSets)\
		+ " B/' CEK= " + Utils::Double2String(totalAvgCheckNum / numDataSets)\
		+ " AND= " + Utils::Double2String(totalAvgANDNum / numDataSets) \
		+ " CMP= " + Utils::Double2String(totalAvgCMPNum / numDataSets) \
		+ " Bingo= " + Utils::Double2String(totalAvgAggBingoNum / numDataSets)\
		+ " Fail= " + Utils::Double2String(totalAvgAggFailNum / numDataSets) + "\n";
	*/
	Utils::WriteData2Begin(file_path, content);
	return 0;
}