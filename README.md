# DoLTEst

# Parts of the specification used for guideline generation (representative statements) 

| Guideline Number| Representative statement | Page# |
|:---------------|:----------------------------------------------|----------------------------------------------------|
| 1 | After having initiated the initial security activation procedure, E-UTRAN initiates the establishment of SRB2 and DRBs   | 68p |
| 2 | SRB2 has a lower-priority than SRB1 and is always configured by E-UTRAN after security activation.                       | 39p |
| 3 | During this initial phase of the RRC connection, the E-UTRAN may configure the UE to perform measurement reporting, but the UE only sends the corresponding measurement reports after successful security activation.                                                                                   | 68p |
| 4 | The message shall not be sent unprotected before security activation if it is used to perform handover or to establish SRB2, SRB4 and DRBs. The PCell can be changed using an RRCConnectionReconfiguration message including the mobilityControlInfo (handover)| 918p, 72p |
| 5, 8, 10 | Annex 6, “-” mark in the Table | 918p |
| 6 | The ‘NULL’ integrity protection algorithm (eia0) is used only for the UE in limited service mode, as specified in TS 33.401. | 70p |
| 7 | E-UTRAN should retrieve UE capabilities only after AS security activation and E-UTRAN does not forward capabilities that were retrieved before AS security activation to the CN.                                                                                                                                | 230p |
| 9 | E-UTRAN initiates the procedure by sending the UEInformationRequest message. E-UTRAN should initiate this procedure only after successful security activation. | 919p |
| 11, 13, 14, 15, 17 | Except the messages listed below, no NAS signalling messages shall be processed by the receiving EMM entity in the UE or forwarded to the ESM entity, unless the network has established secure exchange of NAS messages for the NAS signalling connection. |50p, 51p |
| 12 | The use of "null integrity protection algorithm" EIA0 (see subclause 9.9.3.23) in the current security context is only allowed for an unauthenticated UE for which establishment of emergency bearer services.                                                                                       | 50p |
| 16 | If the ATTACH REJECT message with EMM cause #25 was received without integrity protection, then the UE shall discard the message.  | 129p | 
